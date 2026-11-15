//! The private bus and the scripted polkit of `snap_socket_sign`.

use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::io::{BufRead, BufReader};
use std::os::fd::OwnedFd;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};

use zbus::connection::Builder;
use zbus::{Connection, OwnedVariant, interface};

/// The uid the service itself runs as in the rule of the scripted polkit.
const SERVICE_UID: u32 = 4002;

pub struct Bus {
    child: Child,
    address: String,
}

impl Bus {
    pub fn start() -> Result<Self, Box<dyn Error>> {
        let mut child = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .spawn()?;
        let mut address = String::new();
        BufReader::new(child.stdout.take().ok_or("no stdout")?).read_line(&mut address)?;
        Ok(Self {
            child,
            address: address.trim().to_owned(),
        })
    }

    pub async fn connect(&self) -> Result<Connection, Box<dyn Error>> {
        Ok(Builder::address(self.address.as_str()).build().await?)
    }
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Clone, Copy)]
pub enum Answer {
    Yes,
    No,
    /// An error reply.
    Fail,
    /// An error reply that older polkit gives for a subject it cannot parse.
    OldPolkit,
}

/// What the scripted polkit saw of one question.
#[derive(Debug, Clone)]
pub struct Call {
    pub kind: String,
    pub keys: Vec<String>,
    pub uid: Option<u32>,
    /// `Pid:` of `/proc/self/fdinfo/<fd>` of the received pidfd.
    pub fd_pid: Option<u32>,
    pub action: String,
    pub flags: u32,
}

pub struct FakePolkit {
    pub script: Arc<Mutex<VecDeque<Answer>>>,
    pub calls: Arc<Mutex<Vec<Call>>>,
    /// The caller's own uid; a subject uid that differs is refused unless the shipped policy has the owner.
    pub rule: Option<bool>,
}

fn fdinfo_pid(fd: &OwnedFd) -> Option<u32> {
    let text = std::fs::read_to_string(format!(
        "/proc/self/fdinfo/{}",
        std::os::fd::AsRawFd::as_raw_fd(fd)
    ))
    .ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix("Pid:"))
        .and_then(|v| v.trim().parse().ok())
}

#[interface(name = "org.freedesktop.PolicyKit1.Authority")]
impl FakePolkit {
    // The `interface` macro needs owned argument types to deserialize the D-Bus message.
    #[allow(clippy::needless_pass_by_value)]
    fn check_authorization(
        &self,
        subject: (String, HashMap<String, OwnedVariant>),
        action_id: String,
        details: HashMap<String, String>,
        flags: u32,
        cancellation_id: String,
    ) -> zbus::fdo::Result<(bool, bool, HashMap<String, String>)> {
        let _ = (details, cancellation_id);
        // real polkit reads `uid` as an int32 and ignores any other type
        let uid = subject
            .1
            .get("uid")
            .and_then(|v| i32::try_from(v).ok())
            .and_then(|v| u32::try_from(v).ok());
        let fd_pid = subject
            .1
            .get("pidfd")
            .and_then(|v| OwnedFd::try_from(zbus::Fd::try_from(v.try_clone().ok()?).ok()?).ok())
            .and_then(|fd| fdinfo_pid(&fd));
        let mut keys: Vec<String> = subject.1.keys().cloned().collect();
        keys.sort();
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Call {
                kind: subject.0,
                keys,
                uid,
                fd_pid,
                action: action_id,
                flags,
            });
        let answer = self
            .script
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
            .unwrap_or(Answer::Fail);
        if let (Some(has_owner), Some(uid)) = (self.rule, uid)
            && uid != SERVICE_UID
            && !has_owner
        {
            return Err(zbus::fdo::Error::AccessDenied("not the owner".into()));
        }
        match answer {
            Answer::Yes => Ok((true, false, HashMap::new())),
            Answer::No => Ok((false, false, HashMap::new())),
            Answer::Fail => Err(zbus::fdo::Error::Failed("boom".into())),
            Answer::OldPolkit => Err(zbus::fdo::Error::InvalidArgs(
                "Error parsing unix-process subject".into(),
            )),
        }
    }
}

/// The same method with a reply that is not `(bb a{ss})`.
pub struct GarbledPolkit;

#[interface(name = "org.freedesktop.PolicyKit1.Authority")]
impl GarbledPolkit {
    // The `interface` macro needs owned argument types to deserialize the D-Bus message.
    #[allow(clippy::needless_pass_by_value, clippy::unused_self)]
    fn check_authorization(
        &self,
        subject: (String, HashMap<String, OwnedVariant>),
        action_id: String,
        details: HashMap<String, String>,
        flags: u32,
        cancellation_id: String,
    ) -> String {
        let _ = (subject, action_id, details, flags, cancellation_id);
        "yes".to_owned()
    }
}
