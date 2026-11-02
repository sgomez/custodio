//! `pkttyagent` around the polkit call of `custodio import` and `custodio delete`: the real binary
//! on a pseudo-terminal, a fake `pkttyagent` first on `PATH`, the real service on a private bus
//! with a fake polkit. No real agent is registered.
//!
//! The fake is a shell script that records its pid and `argv`, closes its stdout (the notify
//! descriptor `--notify-fd=1`) the way `pkttyagent` does when it is registered, and then waits.
//! Its behaviour is chosen with `FAKE_MODE` (`late`, `exit`, `fail`, `hang`) and `FAKE_NOHUP`.

#[path = "delete/rig.rs"]
mod rig;
#[path = "delete/run.rs"]
mod run;

use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use custodio_cli::delete::question;
use custodiod::polkit::DELETE_ACTION_ID;

use rig::*;
use run::*;

type TestResult = Result<(), Box<dyn Error>>;

const FAKE: &str = r#"#!/bin/sh
d="$FAKE_DIR"
echo "$$" >> "$d/starts"
for a in "$@"; do printf '%s\n' "$a" >> "$d/args"; done
[ -n "$FAKE_NOHUP" ] && trap '' HUP
case "$FAKE_MODE" in
  exit) exit 0 ;;
  fail) exit 1 ;;
  late) sleep 1; exec 1>&-; : > "$d/closed" ;;
  hang) ;;
  *) exec 1>&-; : > "$d/closed" ;;
esac
while :; do sleep 1; done
"#;

/// A directory with the fake `pkttyagent` and a link to the real `setpriv`.
struct Kit {
    dir: tempfile::TempDir,
}

/// Makes this test process a child subreaper, once. A descendant orphaned by the CLI then
/// becomes this process's child instead of PID 1's: if the CLI did not reap the agent, the agent
/// stays a zombie (`/proc/<pid>` exists) and `gone` fails. Without it PID 1 would reap it.
fn subreaper() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: `prctl` with an integer argument; it only changes this process's attributes.
        let rc = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
        assert_eq!(rc, 0, "PR_SET_CHILD_SUBREAPER");
    });
}

impl Kit {
    fn new() -> Result<Self, Box<dyn Error>> {
        subreaper();
        let dir = tempfile::tempdir()?;
        let bin = dir.path().join("bin");
        fs::create_dir(&bin)?;
        fs::write(bin.join("pkttyagent"), FAKE)?;
        fs::set_permissions(bin.join("pkttyagent"), fs::Permissions::from_mode(0o755))?;
        std::os::unix::fs::symlink("/usr/bin/setpriv", bin.join("setpriv"))?;
        Ok(Self { dir })
    }

    fn path(&self) -> String {
        format!("{}:/usr/bin:/bin", self.dir.path().join("bin").display())
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The environment of the CLI: the fake first on `PATH`, behaviour `mode`.
    fn env(&self, mode: &str, nohup: bool) -> Vec<(String, String)> {
        let mut env = vec![
            ("PATH".to_owned(), self.path()),
            ("FAKE_DIR".to_owned(), self.dir.path().display().to_string()),
            ("FAKE_MODE".to_owned(), mode.to_owned()),
        ];
        if nohup {
            env.push(("FAKE_NOHUP".to_owned(), "1".to_owned()));
        }
        env
    }

    fn lines(&self, name: &str) -> Vec<String> {
        fs::read_to_string(self.file(name))
            .map(|t| t.lines().map(str::to_owned).collect())
            .unwrap_or_default()
    }

    fn pids(&self) -> Vec<u32> {
        self.lines("starts")
            .iter()
            .filter_map(|l| l.parse().ok())
            .collect()
    }

    fn wait_started(&self) -> Result<u32, Box<dyn Error>> {
        wait_until("the fake agent to start", || !self.pids().is_empty())?;
        Ok(self.pids()[0])
    }
}

fn wait_until(what: &str, mut condition: impl FnMut() -> bool) -> TestResult {
    let start = Instant::now();
    while !condition() {
        if start.elapsed() > WAIT {
            return Err(format!("timed out waiting for {what}").into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

fn gone(pid: u32) -> bool {
    !Path::new(&format!("/proc/{pid}")).exists()
}

/// The fields of `/proc/<pid>/stat` after the command name, which is in parentheses.
fn stat_fields(pid: u32) -> Result<Vec<String>, Box<dyn Error>> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let (_, after) = stat.rsplit_once(')').ok_or("no )")?;
    Ok(after.split_whitespace().map(str::to_owned).collect())
}

/// Field 22 of `/proc/<pid>/stat`: it is the 20th after the command name and the state.
fn start_time(pid: u32) -> Result<String, Box<dyn Error>> {
    Ok(stat_fields(pid)?.get(19).ok_or("short stat")?.clone())
}

fn state(pid: u32) -> Result<String, Box<dyn Error>> {
    Ok(stat_fields(pid)?.first().ok_or("short stat")?.clone())
}

fn signal(pid: u32, sig: i32) {
    // SAFETY: `kill` on a pid this test started.
    let rc = unsafe { libc::kill(i32::try_from(pid).unwrap_or(0), sig) };
    assert_eq!(rc, 0);
}

fn borrow(env: &[(String, String)]) -> Vec<(&str, &str)> {
    env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

/// A rig with the key `k` imported and the fake polkit in `mode`.
fn rig_with_key(mode: Polkit) -> Result<Rig, Box<dyn Error>> {
    let rig = Rig::start(true)?;
    rig.import("k")?;
    rig.forget();
    rig.polkit(mode);
    Ok(rig)
}

/// `custodio delete k` on a terminal that is also its standard input, answered with `answer`.
fn delete_on_tty(rig: &Rig, kit: &Kit, mode: &str, answer: &[u8]) -> Result<Run, Box<dyn Error>> {
    let env = kit.env(mode, false);
    let mut run = Run::start_with(rig, &["delete", "k"], &borrow(&env), true, Stdin::Tty)?;
    run.wait_for(&question("k"))?;
    run.send(answer)?;
    Ok(run)
}

fn expected_args(cli_pid: u32) -> Result<Vec<String>, Box<dyn Error>> {
    Ok(vec![
        "--fallback".to_owned(),
        "--notify-fd=1".to_owned(),
        format!("--process={cli_pid},{}", start_time(cli_pid)?),
    ])
}

#[test]
fn delete_starts_the_agent_for_the_cli_process_only_after_the_answer() -> TestResult {
    let rig = rig_with_key(Polkit::Hold)?;
    let kit = Kit::new()?;
    let env = kit.env("ok", false);
    let mut run = Run::start_with(&rig, &["delete", "k"], &borrow(&env), true, Stdin::Tty)?;
    run.wait_for(&question("k"))?;
    // Not before the prompt is answered.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(kit.pids(), Vec::<u32>::new());
    run.send(b"yes\n")?;
    let agent = kit.wait_started()?;
    wait_until("the agent to be registered", || kit.file("closed").exists())?;
    wait_until("polkit to be asked", || !rig.polkit_asked().is_empty())?;
    // Exactly once, during the authorizing call, with the arguments of the CLI's process only.
    assert_eq!(kit.pids(), [agent]);
    assert_eq!(rig.polkit_asked(), [DELETE_ACTION_ID.to_owned()]);
    assert_eq!(kit.lines("args"), expected_args(run.child.id())?);
    signal(run.child.id(), libc::SIGINT);
    run.finish()?;
    wait_until("the agent to be gone", || gone(agent))
}

#[test]
fn import_starts_the_agent_for_the_cli_process_only_after_the_password() -> TestResult {
    let rig = Rig::start(true)?;
    rig.polkit(Polkit::Hold);
    let kit = Kit::new()?;
    let file = rig.dir.path().join("k.p12");
    fs::write(&file, P256_P12)?;
    let file = file.display().to_string();
    let env = kit.env("ok", false);
    let mut run = Run::start_with(&rig, &["import", &file], &borrow(&env), true, Stdin::Tty)?;
    run.wait_for("Password for")?;
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(kit.pids(), Vec::<u32>::new());
    run.send(format!("{PASSWORD}\n").as_bytes())?;
    let agent = kit.wait_started()?;
    wait_until("polkit to be asked", || !rig.polkit_asked().is_empty())?;
    assert_eq!(kit.pids(), [agent]);
    assert_eq!(kit.lines("args"), expected_args(run.child.id())?);
    signal(run.child.id(), libc::SIGINT);
    let done = run.finish()?;
    assert!(!done.stdout.contains(PASSWORD) && !done.stderr.contains(PASSWORD));
    wait_until("the agent to be gone", || gone(agent))
}

#[test]
fn no_agent_without_a_terminal_as_standard_input() -> TestResult {
    // A controlling terminal for the prompt, but standard input is a pipe, then a file.
    for stdin in [Stdin::Pipe(b"no\n"), Stdin::File] {
        let rig = rig_with_key(Polkit::Approve)?;
        let kit = Kit::new()?;
        let env = kit.env("ok", false);
        let mut run = Run::start_with(&rig, &["delete", "k"], &borrow(&env), true, stdin)?;
        run.wait_for(&question("k"))?;
        run.send(b"yes\n")?;
        let done = run.finish()?;
        assert_eq!(done.status.code(), Some(0), "{}", done.stderr);
        assert_eq!(rig.polkit_asked(), [DELETE_ACTION_ID.to_owned()]);
        assert_eq!(kit.pids(), Vec::<u32>::new());
    }
    Ok(())
}

#[test]
fn no_agent_for_a_declined_or_refused_command() -> TestResult {
    let kit = Kit::new()?;
    // Declined on a terminal.
    let rig = rig_with_key(Polkit::Approve)?;
    let done = delete_on_tty(&rig, &kit, "ok", b"n\n")?.finish()?;
    assert_eq!(done.status.code(), Some(1));
    assert_eq!(rig.polkit_asked(), Vec::<String>::new());
    // Standard input is a terminal but there is no controlling terminal to confirm on.
    let env = kit.env("ok", false);
    let run = Run::start_with(&rig, &["delete", "k"], &borrow(&env), false, Stdin::Tty)?;
    assert_eq!(run.finish()?.status.code(), Some(1));
    // A usage error.
    let run = Run::start_with(&rig, &["import"], &borrow(&env), true, Stdin::Tty)?;
    assert_eq!(run.finish()?.status.code(), Some(2));
    assert_eq!(kit.pids(), Vec::<u32>::new());
    Ok(())
}

#[test]
fn the_agent_is_gone_after_success_and_after_failure() -> TestResult {
    for (mode, code) in [(Polkit::Approve, 0), (Polkit::Deny, 1)] {
        let rig = rig_with_key(mode)?;
        let kit = Kit::new()?;
        let done = delete_on_tty(&rig, &kit, "ok", b"yes\n")?.finish()?;
        assert_eq!(done.status.code(), Some(code), "{}", done.stderr);
        let agent = kit.wait_started()?;
        wait_until("the agent to be gone", || gone(agent))?;
    }
    Ok(())
}

#[test]
fn an_interruption_stops_the_agent_and_exits_non_zero() -> TestResult {
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        let rig = rig_with_key(Polkit::Hold)?;
        let kit = Kit::new()?;
        let run = delete_on_tty(&rig, &kit, "ok", b"yes\n")?;
        let agent = kit.wait_started()?;
        wait_until("polkit to be asked", || !rig.polkit_asked().is_empty())?;
        signal(run.child.id(), sig);
        let done = run.finish()?;
        assert_eq!(done.status.code(), Some(130), "signal {sig}");
        wait_until("the agent to be gone", || gone(agent))?;
    }
    Ok(())
}

#[test]
fn the_call_waits_for_the_agent_to_register() -> TestResult {
    let rig = rig_with_key(Polkit::Hold)?;
    let kit = Kit::new()?;
    let run = delete_on_tty(&rig, &kit, "late", b"yes\n")?;
    let agent = kit.wait_started()?;
    std::thread::sleep(Duration::from_millis(400));
    // The fake has not closed the notify descriptor: polkit has not been asked.
    assert!(!kit.file("closed").exists());
    assert_eq!(rig.polkit_asked(), Vec::<String>::new());
    wait_until("the agent to be registered", || kit.file("closed").exists())?;
    wait_until("polkit to be asked", || !rig.polkit_asked().is_empty())?;
    signal(run.child.id(), libc::SIGINT);
    run.finish()?;
    wait_until("the agent to be gone", || gone(agent))
}

#[test]
fn an_agent_that_ends_or_never_says_anything_does_not_hang_the_cli() -> TestResult {
    for mode in ["exit", "fail", "hang"] {
        let rig = rig_with_key(Polkit::Approve)?;
        let kit = Kit::new()?;
        let start = Instant::now();
        let done = delete_on_tty(&rig, &kit, mode, b"yes\n")?.finish()?;
        assert_eq!(done.status.code(), Some(0), "{mode}: {}", done.stderr);
        assert_eq!(done.stdout, "Deleted key 'k'.\n");
        assert_eq!(done.stderr, "");
        assert!(start.elapsed() < WAIT, "{mode}");
        let agent = kit.wait_started()?;
        wait_until("the agent to be gone", || gone(agent))?;
    }
    Ok(())
}

#[test]
fn a_missing_pkttyagent_or_setpriv_starts_no_agent_and_adds_no_text() -> TestResult {
    // The reference run: the fake agent works.
    let rig = rig_with_key(Polkit::Deny)?;
    let kit = Kit::new()?;
    let reference = delete_on_tty(&rig, &kit, "ok", b"yes\n")?.finish()?;
    assert_eq!(reference.status.code(), Some(1));
    for links in [true, false] {
        let rig = rig_with_key(Polkit::Deny)?;
        let empty = tempfile::tempdir()?;
        if links {
            // `setpriv` is found but there is no `pkttyagent` behind it.
            std::os::unix::fs::symlink("/usr/bin/setpriv", empty.path().join("setpriv"))?;
        }
        let path = empty.path().display().to_string();
        let mut run =
            Run::start_with(&rig, &["delete", "k"], &[("PATH", &path)], true, Stdin::Tty)?;
        run.wait_for(&question("k"))?;
        run.send(b"yes\n")?;
        let done = run.finish()?;
        assert_eq!(done.status.code(), Some(1));
        assert_eq!(done.stdout, reference.stdout);
        assert_eq!(done.stderr, reference.stderr);
    }
    Ok(())
}

#[test]
fn a_killed_cli_leaves_no_agent_running() -> TestResult {
    let rig = rig_with_key(Polkit::Hold)?;
    let kit = Kit::new()?;
    // The CLI is a background job of the session leader, and the fake ignores SIGHUP.
    let env = kit.env("ok", true);
    let mut run = Run::start_in_shell(&rig, &["delete", "k"], &borrow(&env))?;
    run.wait_for(&question("k"))?;
    run.send(b"yes\n")?;
    let agent = kit.wait_started()?;
    wait_until("polkit to be asked", || !rig.polkit_asked().is_empty())?;
    let cli: u32 = fs::read_to_string(rig.dir.path().join("cli.pid"))?
        .trim()
        .parse()?;
    assert_ne!(cli, run.child.id());
    assert!(!gone(agent));
    signal(cli, libc::SIGKILL);
    run.finish()?;
    // Nobody is left to reap the agent: gone, or a zombie under this subreaper.
    wait_until("the agent to be gone", || {
        gone(agent) || state(agent).is_ok_and(|s| s == "Z")
    })
}

#[test]
fn a_failed_import_shows_no_secret() -> TestResult {
    let rig = Rig::start(true)?;
    rig.polkit(Polkit::Deny);
    let kit = Kit::new()?;
    let file = rig.dir.path().join("k.p12");
    fs::write(&file, P256_P12)?;
    let file = file.display().to_string();
    let env = kit.env("ok", false);
    let mut run = Run::start_with(&rig, &["import", &file], &borrow(&env), true, Stdin::Tty)?;
    run.wait_for("Password for")?;
    run.send(format!("{PASSWORD}\n").as_bytes())?;
    let done = run.finish()?;
    assert_eq!(done.status.code(), Some(1));
    let all = format!("{}{}", done.stdout, done.stderr);
    for secret in [PASSWORD, file.as_str()] {
        assert!(!all.contains(secret), "output holds {secret}");
    }
    // Nor any run of the file's bytes.
    assert!(!all.as_bytes().windows(16).any(|w| w == &P256_P12[..16]));
    Ok(())
}
