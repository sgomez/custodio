//! More calls than TPM object slots (F130): the real service on a private bus with fake polkit, a real `swtpm` and the
//! in-memory journal. Everything goes through the bus (`ImportP12`, `Sign`, `ListKeys`).
//!
//! The `swtpm` has no resource manager, so an object the service leaves loaded stays loaded until a flush. The number of
//! calls is derived from the slot count the TPM reports. Calls that fail midway go through the `tpm_filter` in front
//! of the `swtpm`: error responses the code flushes after (class one), and connection drops and a failed flush, which
//! leave handles that the kernel resource manager would clean up (class two; `tpm2_flushcontext -t` stands in for it).
//!
//! The per-call flush at the library level and 30 direct signs / 10 direct imports are `tpm_sign` and `tpm_import`;
//! the cleared TPM is `tpm_lifecycle`; `encrypted-tpm` keys use no TPM object per call and are not here.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

// The shared helpers are used in full by other tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/bus.rs"]
mod bus;
// The shared helpers are used in full by other tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/common.rs"]
mod common;
// Shared with `sign_kinds`: this target does not use every helper of it.
#[allow(dead_code, unused_imports)]
#[path = "sign_kinds/kit.rs"]
mod kit;
// Shared with `tpm_sign`: this target does not use every helper of it.
#[allow(dead_code)]
#[path = "tpm_sign/oracle.rs"]
mod oracle;
// Shared with `storage_choice`: this target does not use every helper of it.
#[allow(dead_code)]
#[path = "storage_choice/rig.rs"]
mod rig;
// Shared with `tpm_import`: this target does not use every helper of it.
#[allow(dead_code, unused_imports)]
#[path = "tpm_import/support.rs"]
mod support;

use custodio_it::tpm_filter::{CommandFault, FaultAction, Lacks, TpmFilter, cc};
use custodiod::store::Kind;
use custodiod::tpm::open::TestTcti;
use zbus::block_on;

use common::SENTINEL_PASSWORD;
use kit::{ERR_KEY_LOST, ERR_UNAVAILABLE, Family, der_to_pem};
use rig::{ERR_TPM, KindSvc, Res, SUBJECTS, Subject, TestResult};

/// The most transient slots the test accepts. The runs are `3 * slots + MARGIN` calls of two key types each, with
/// an `openssl` run per signature, so a TPM with many slots would turn the test into a long one; `swtpm` reports 3.
const MAX_SLOTS: usize = 16;

/// Calls beyond three times the slot count, so a run is longer than the slots even if a call used none.
const MARGIN: usize = 2;

/// The error response the service does not read as "this TPM lacks the command", so it fails closed.
const NOT_LACKING: u32 = 0x101;

/// The transient-object count out of `tpm2_getcap properties-fixed`: the line after the name must give a hex value.
fn parse_slots(text: &str) -> Result<usize, String> {
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if line.trim() == "TPM2_PT_HR_TRANSIENT_MIN:" {
            let raw = lines
                .next()
                .and_then(|l| l.trim().strip_prefix("raw:"))
                .ok_or("the capability has no value line")?;
            return usize::from_str_radix(raw.trim().trim_start_matches("0x"), 16)
                .map_err(|e| format!("the capability value is not a number: {e}"));
        }
    }
    Err("no TPM2_PT_HR_TRANSIENT_MIN in the capabilities".to_owned())
}

fn slot_count(rig: &rig::Rig) -> usize {
    let slots = parse_slots(&rig.getcap("properties-fixed").unwrap()).unwrap();
    assert!((1..=MAX_SLOTS).contains(&slots), "slots: {slots}");
    slots
}

fn calls_for(slots: usize) -> usize {
    slots * 3 + MARGIN
}

fn fault(command: u32, action: FaultAction) -> Lacks {
    Lacks {
        faults: vec![CommandFault { command, action }],
        ..Lacks::default()
    }
}

/// The command that signs for this key type.
fn sign_command(subject: Subject) -> u32 {
    if subject.reply == "rsa2048" {
        cc::RSA_DECRYPT
    } else {
        cc::SIGN
    }
}

/// A fault in place: the filter is in front of the `swtpm` for the service until [`Fx::lift`].
struct Faulted {
    filter: TpmFilter,
    record: custodio_it::tpm_filter::Recorder,
}

/// The service on a `swtpm`, with the slot count read from the TPM.
struct Fx {
    k: KindSvc,
    slots: usize,
}

impl Fx {
    async fn new() -> Res<Self> {
        let k = KindSvc::start(Kind::Tpm).await?;
        let slots = slot_count(&k.rig);
        Ok(Self { k, slots })
    }

    fn put(&self, lacks: Lacks) -> Faulted {
        let (filter, record) = self.k.rig.filter(lacks).unwrap();
        self.k.svc.tpm.swap(TestTcti::new(&filter.tcti()));
        Faulted { filter, record }
    }

    /// Takes the filter away and gives the commands it saw.
    fn lift(&self, faulted: Faulted) -> Vec<u32> {
        self.k.svc.tpm.swap(TestTcti::new(&self.k.rig.tcti()));
        let codes = faulted.record.codes();
        drop(faulted.filter);
        codes
    }

    /// `ImportP12` of the subject's key under `id`: the key type and the kind of the reply, or the error name.
    async fn import(&self, id: &str, subject: Subject) -> Result<(String, String), String> {
        let reply = self
            .k
            .svc
            .call_method("ImportP12", &(id, subject.p12.to_vec(), SENTINEL_PASSWORD))
            .await?;
        reply.body().deserialize().map_err(|e| e.to_string())
    }

    async fn list(&self) -> Vec<(String, String, String, Vec<u8>)> {
        let reply = self.k.svc.call_method("ListKeys", &()).await.unwrap();
        let mut listed: Vec<_> = reply.body().deserialize().unwrap();
        listed.sort();
        listed
    }

    async fn sign(&self, id: &str, subject: Subject) -> Result<Vec<u8>, String> {
        let (mechanism, hash, salt, data) = Family::of(subject)[0].args();
        let reply = self
            .k
            .svc
            .call_method("Sign", &(id, mechanism, hash, salt, data))
            .await?;
        reply.body().deserialize().map_err(|e| e.to_string())
    }

    /// One `Sign`, whose signature `openssl` verifies with the certificate `ListKeys` shows for `id`.
    async fn sign_verified(&self, id: &str, subject: Subject) -> TestResult {
        let signature = self.sign(id, subject).await?;
        let listed = self.list().await;
        let cert = &listed.iter().find(|l| l.0 == id).unwrap().3;
        let pem = der_to_pem(&self.k.rig, "check.pem", cert);
        assert!(
            Family::of(subject)[0].verifies(&self.k.rig, &pem, &signature)?,
            "{id}: not verified"
        );
        Ok(())
    }

    /// More signatures than slots, each verified when `all` is set, otherwise the last one.
    async fn sign_run(&self, id: &str, subject: Subject, all: bool) -> TestResult {
        let calls = calls_for(self.slots);
        assert!(calls > self.slots);
        for i in 0..calls {
            if all || i + 1 == calls {
                self.sign_verified(id, subject).await?;
            } else {
                self.sign(id, subject)
                    .await
                    .map_err(|e| format!("{id}, call {i}: {e}"))?;
            }
        }
        Ok(())
    }

    /// More imports than slots, each a new id; all report kind `tpm`. Gives the ids.
    async fn import_run(&self, subject: Subject, prefix: &str) -> Res<Vec<String>> {
        let calls = calls_for(self.slots);
        assert!(calls > self.slots);
        let mut ids = Vec::new();
        for i in 0..calls {
            let id = format!("{prefix}-{i}");
            let (key_type, kind) = self
                .import(&id, subject)
                .await
                .map_err(|e| format!("{id}: {e}"))?;
            assert_eq!(
                (key_type.as_str(), kind.as_str()),
                (subject.reply, Kind::Tpm.wire())
            );
            ids.push(id);
        }
        Ok(ids)
    }

    fn assert_nothing_loaded(&self, context: &str) {
        self.k.rig.assert_nothing_loaded(context).unwrap();
    }

    /// What the kernel resource manager would do when the connection closes.
    fn stand_in_flush(&self) {
        self.k.rig.tpm.tool_ok("tpm2_flushcontext", ["-t"]).unwrap();
    }

    fn handles_left(&self) -> usize {
        self.k.rig.handles("handles-transient").unwrap().len()
    }
}

#[test]
fn slot_count_is_reported() -> TestResult {
    let rig = rig::Rig::new()?;
    let text = rig.getcap("properties-fixed")?;
    let slots = slot_count(&rig);
    assert_eq!(parse_slots(&text), Ok(slots));
    // Control: the parser does not invent a default.
    let without_name = text
        .lines()
        .filter(|l| !l.contains("TPM2_PT_HR_TRANSIENT_MIN"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(parse_slots(&without_name).is_err());
    let mut lines = text.lines().peekable();
    let mut without_value = String::new();
    while let Some(line) = lines.next() {
        without_value.push_str(line);
        without_value.push('\n');
        if line.trim() == "TPM2_PT_HR_TRANSIENT_MIN:" {
            lines.next();
        }
    }
    assert!(parse_slots(&without_value).is_err());
    assert!(parse_slots("").is_err());
    Ok(())
}

#[test]
fn signatures_exceed_slots() -> TestResult {
    block_on(async {
        let fx = Fx::new().await?;
        for subject in SUBJECTS {
            let id = format!("sign-{}", subject.reply);
            fx.import(&id, subject).await?;
            fx.sign_run(&id, subject, true).await?;
            fx.assert_nothing_loaded(&format!("after the signatures of {}", subject.reply));
        }
        // Control: a client that leaks `slots` objects makes the next `Sign` fail, so a leak would be seen.
        let subject = SUBJECTS[1];
        let id = format!("sign-{}", subject.reply);
        for _ in 0..fx.slots {
            fx.k.rig.tpm.tool_ok(
                "tpm2_createprimary",
                ["-C", "o", "-c", &fx.k.rig.path("leak.ctx")],
            )?;
        }
        assert_eq!(fx.handles_left(), fx.slots);
        assert!(fx.sign(&id, subject).await.is_err(), "a full TPM signs");
        fx.stand_in_flush();
        fx.sign_verified(&id, subject).await?;
        Ok(())
    })
}

#[test]
fn imports_exceed_slots() -> TestResult {
    block_on(async {
        let fx = Fx::new().await?;
        let mut last = Vec::new();
        let mut all = Vec::new();
        for subject in SUBJECTS {
            let ids = fx.import_run(subject, subject.reply).await?;
            all.extend(ids.iter().cloned());
            last.push((ids.last().unwrap().clone(), subject));
        }
        fx.assert_nothing_loaded("after the imports");
        all.sort();
        let listed: Vec<String> = fx.list().await.into_iter().map(|l| l.0).collect();
        assert_eq!(listed, all);
        for (id, subject) in last {
            fx.sign_verified(&id, subject).await?;
        }
        fx.assert_nothing_loaded("after the signatures");
        Ok(())
    })
}

#[test]
fn failed_signatures_leave_no_slot_used() -> TestResult {
    block_on(async {
        let fx = Fx::new().await?;
        for subject in SUBJECTS {
            let id = format!("sign-{}", subject.reply);
            fx.import(&id, subject).await?;
            fx.sign_verified(&id, subject).await?;
            let sign = sign_command(subject);

            // Class one: an error response, and the service flushes all the same, repeated beyond the slots.
            for command in [cc::CREATE_PRIMARY, cc::LOAD, sign] {
                let faulted = fx.put(fault(command, FaultAction::Respond(NOT_LACKING)));
                for i in 0..=fx.slots {
                    let error = fx.sign(&id, subject).await.unwrap_err();
                    // A blob that does not load is reported as a lost key; any other failure as unavailable.
                    let want = if command == cc::LOAD {
                        ERR_KEY_LOST
                    } else {
                        ERR_UNAVAILABLE
                    };
                    assert_eq!(error, want, "{command:#x}, call {i}");
                }
                let codes = fx.lift(faulted);
                assert!(codes.contains(&command), "{command:#x} never reached");
                fx.assert_nothing_loaded(&format!("after failed {command:#x}"));
                fx.sign_run(&id, subject, false).await?;
            }

            // Class two: the service cannot flush; the resource manager's job is done by the test.
            for (command, action) in [
                (cc::CREATE_PRIMARY, FaultAction::DropMidReply),
                (cc::LOAD, FaultAction::DropMidReply),
                (sign, FaultAction::DropMidReply),
                (cc::FLUSH_CONTEXT, FaultAction::Respond(NOT_LACKING)),
            ] {
                fx.sign_verified(&id, subject).await?;
                let faulted = fx.put(fault(command, action));
                let result = fx.sign(&id, subject).await;
                let codes = fx.lift(faulted);
                assert!(result.is_err(), "{command:#x} {action:?}: {result:?}");
                assert!(codes.contains(&command), "{command:#x} never reached");
                if command != cc::CREATE_PRIMARY {
                    assert!(
                        fx.handles_left() > 0,
                        "{command:#x} {action:?} left no handle"
                    );
                }
                fx.stand_in_flush();
                fx.assert_nothing_loaded(&format!("after {command:#x} {action:?}"));
            }
            fx.sign_run(&id, subject, true).await?;
            fx.assert_nothing_loaded("after the last run");
        }
        Ok(())
    })
}

#[test]
fn failed_imports_leave_no_slot_used() -> TestResult {
    block_on(async {
        let fx = Fx::new().await?;
        for subject in SUBJECTS {
            let before = (fx.list().await, fx.k.svc.files());

            // Class one: an error response, repeated beyond the slots; no key is stored.
            for command in [cc::CREATE_PRIMARY, cc::IMPORT] {
                let faulted = fx.put(fault(command, FaultAction::Respond(NOT_LACKING)));
                for i in 0..=fx.slots {
                    let error = fx.import("failing", subject).await.unwrap_err();
                    assert_eq!(error, ERR_TPM, "{command:#x}, call {i}");
                }
                let codes = fx.lift(faulted);
                assert!(codes.contains(&command), "{command:#x} never reached");
                fx.assert_nothing_loaded(&format!("after failed {command:#x}"));
                assert_eq!((fx.list().await, fx.k.svc.files()), before);
            }

            // Class two: drops and a failed flush.
            for (command, action) in [
                (cc::CREATE_PRIMARY, FaultAction::DropMidReply),
                (cc::IMPORT, FaultAction::DropMidReply),
                (cc::FLUSH_CONTEXT, FaultAction::Respond(NOT_LACKING)),
            ] {
                let faulted = fx.put(fault(command, action));
                let result = fx.import("failing", subject).await;
                let codes = fx.lift(faulted);
                assert!(result.is_err(), "{command:#x} {action:?}: {result:?}");
                assert!(codes.contains(&command), "{command:#x} never reached");
                if command != cc::CREATE_PRIMARY {
                    assert!(
                        fx.handles_left() > 0,
                        "{command:#x} {action:?} left no handle"
                    );
                }
                fx.stand_in_flush();
                fx.assert_nothing_loaded(&format!("after {command:#x} {action:?}"));
                assert_eq!((fx.list().await, fx.k.svc.files()), before);
            }
        }
        // After the last fault: more imports than slots of each type, and a verified signature.
        for subject in SUBJECTS {
            let ids = fx.import_run(subject, subject.reply).await?;
            fx.sign_verified(ids.last().unwrap(), subject).await?;
        }
        fx.assert_nothing_loaded("after the imports");
        Ok(())
    })
}
