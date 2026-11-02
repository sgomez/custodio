//! The case on every outcome, and no effect of the case on anything else.

use super::*;

#[test]
fn app_id_on_every_outcome() -> TestResult {
    zbus::block_on(async {
        // (answer of polkit, failure after the approval, operations it applies to)
        let runs = [
            (Answer::No, Fail::No),
            (Answer::Fail, Fail::No),
            (Answer::Yes, Fail::AfterApproval),
        ];
        for (answer, fail) in runs {
            for op in Operation::all() {
                if op == Operation::Delete && fail == Fail::AfterApproval {
                    continue;
                }
                for case in answers()? {
                    let sink = Arc::new(Sink::default());
                    let source = GuardedSource::new(Probe::new(case.clone()));
                    let f = start(op, answer, &sink, Some(source)).await?;
                    let reply = drive(&f, op, fail).await;
                    assert!(reply.is_err(), "{op:?} {reply:?}");
                    let all = sink.fields();
                    assert_eq!(all.len(), 1, "{op:?}");
                    assert_case(all.first().ok_or("entry")?, &case);
                }
            }
        }
        Ok(())
    })
}

/// What one run leaves: the reply, the polkit requests, the store and the entries.
#[derive(PartialEq, Debug)]
struct Result3 {
    reply: Result<(), String>,
    asked: Vec<String>,
    requests: Vec<(String, u32)>,
    store: BTreeMap<String, Vec<u8>>,
    entries: Vec<Vec<(&'static str, String)>>,
}

async fn run(
    op: Operation,
    answer: Answer,
    fail_sink: bool,
    source: Option<AppIdOutcome>,
) -> Result<Result3, Box<dyn Error>> {
    let sink = Arc::new(Sink::default());
    let source = source.map(|c| GuardedSource::new(Probe::new(c)));
    let f = start(op, answer, &sink, source).await?;
    sink.fail.store(fail_sink, Ordering::SeqCst);
    let reply = drive(&f, op, Fail::No).await;
    let without_app_id = |fields: Vec<(&'static str, String)>| {
        fields
            .into_iter()
            .filter(|(n, _)| !n.starts_with("CUSTODIO_APP_ID"))
            .collect::<Vec<_>>()
    };
    Ok(Result3 {
        reply,
        asked: f.asked(),
        requests: f.requests.lock().map(|r| r.clone()).unwrap_or_default(),
        store: snapshot(f.store_dir())?,
        entries: sink.fields().into_iter().map(without_app_id).collect(),
    })
}

#[test]
fn app_id_never_changes_the_outcome() -> TestResult {
    zbus::block_on(async {
        let runs = [
            (Answer::Yes, false),
            (Answer::No, false),
            (Answer::Fail, false),
            (Answer::Yes, true),
        ];
        for op in Operation::all() {
            for (answer, fail_sink) in runs {
                let base = run(op, answer, fail_sink, None).await?;
                for case in answers()? {
                    let with = run(op, answer, fail_sink, Some(case.clone())).await?;
                    assert_eq!(with, base, "{op:?} {fail_sink} {}", app_id_state(&case));
                }
            }
        }
        // The control: the comparison sees a difference when the outcome differs.
        let yes = run(Operation::Delete, Answer::Yes, false, None).await?;
        let no = run(Operation::Delete, Answer::No, false, None).await?;
        assert_ne!(yes, no);
        Ok(())
    })
}
