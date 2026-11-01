//! A replace at the same time as a `ListKeys`, and at the same time as a `DeleteKey`.

use std::future::Future;
use std::sync::atomic::Ordering;
use std::task::Poll;

use custodio_client::ERROR_NO_SUCH_KEY;
use zbus::block_on;

use super::bus::{Answer, TestResult, call};
use super::common::EC_P12;
use super::{NONE, P256_RECERT, Rig, certificate_of, list, names, replace};

/// Polls both futures from one task until both are done. After about 300 ms of polling `release`
/// runs once.
async fn join2<A: Future, B: Future>(a: A, b: B, release: impl Fn()) -> (A::Output, B::Output) {
    let (mut a, mut b) = (Box::pin(a), Box::pin(b));
    let (mut done_a, mut done_b) = (None, None);
    let mut turns = 0_u32;
    std::future::poll_fn(|cx| {
        turns += 1;
        if turns == 60 {
            release();
        }
        if turns < 60 {
            std::thread::sleep(std::time::Duration::from_millis(5));
            cx.waker().wake_by_ref();
        }
        if done_a.is_none()
            && let Poll::Ready(v) = a.as_mut().poll(cx)
        {
            done_a = Some(v);
        }
        if done_b.is_none()
            && let Poll::Ready(v) = b.as_mut().poll(cx)
        {
            done_b = Some(v);
        }
        match (done_a.take(), done_b.take()) {
            (Some(x), Some(y)) => Poll::Ready((x, y)),
            (x, y) => {
                done_a = x;
                done_b = y;
                Poll::Pending
            }
        }
    })
    .await
}

#[test]
fn concurrent_list_sees_old_or_new() -> TestResult {
    block_on(async {
        let r = Rig::start(Answer::Yes, 1000, 1001).await?;
        r.import(r.a(), "k", EC_P12, Answer::Yes).await?;
        let original = certificate_of(r.a(), "k").await?;
        let allowed = [original, P256_RECERT.to_vec(), super::P256_EXPIRED.to_vec()];
        let stop = std::sync::atomic::AtomicBool::new(false);
        let writer = async {
            for round in 0..60_usize {
                let cert = if round % 2 == 0 {
                    P256_RECERT
                } else {
                    super::P256_EXPIRED
                };
                replace(r.a(), "k", cert).await?;
            }
            stop.store(true, Ordering::SeqCst);
            Ok::<_, String>(())
        };
        let reader = async {
            let mut lists = 0_usize;
            while !stop.load(Ordering::SeqCst) {
                let keys = list(&r.a2)
                    .await
                    .map_err(|e| format!("ListKeys failed: {e}"))?;
                let [(id, _, cert)] = keys.as_slice() else {
                    return Err(format!("{} keys listed", keys.len()));
                };
                if id != "k" || !allowed.contains(cert) {
                    return Err("a certificate that is neither old nor new".to_owned());
                }
                lists += 1;
            }
            Ok(lists)
        };
        let (w, l) = join2(writer, reader, || ()).await;
        w?;
        assert!(l? > 0);
        assert_eq!(names(&r.area(1000))?, ["k", "k-cert"]);
        Ok(())
    })
}

#[test]
fn concurrent_replace_and_delete() -> TestResult {
    block_on(async {
        let r = Rig::start(Answer::Yes, 1000, 1001).await?;
        let (mut replaced_first, mut deleted_first) = (0_u32, 0_u32);
        for round in 0..24_usize {
            let id = format!("r{round}");
            r.import(r.a(), &id, EC_P12, Answer::Yes).await?;
            // The first call is held in polkit and the second waits for it (they never interleave);
            // the order of arrival alternates.
            r.f.hold.store(usize::MAX, Ordering::SeqCst);
            let release = &r.f.hold;
            let del = async {
                call(&r.a2, "DeleteKey", &(id.as_str(),))
                    .await
                    .map(|_| ())
                    .map_err(|e| super::error_name(&e))
            };
            let (rep, del) = if round % 2 == 0 {
                join2(replace(r.a(), &id, P256_RECERT), del, || {
                    release.store(0, Ordering::SeqCst);
                })
                .await
            } else {
                let (d, p) = join2(del, replace(r.a(), &id, P256_RECERT), || {
                    release.store(0, Ordering::SeqCst);
                })
                .await;
                (p, d)
            };
            r.f.hold.store(0, Ordering::SeqCst);
            // The delete always succeeds, so neither file is left: never a certificate without its
            // key. A replace that came after the delete saw `NoSuchKey`.
            assert_eq!(del, Ok(()), "round {round}");
            assert_eq!(names(&r.area(1000))?, NONE, "round {round}");
            if rep == Ok(()) {
                replaced_first += 1;
            } else {
                assert_eq!(rep, Err(ERROR_NO_SUCH_KEY.to_owned()), "round {round}");
                deleted_first += 1;
            }
            // The id can be imported again, with a certificate of its own.
            r.import(r.a(), &id, EC_P12, Answer::Yes).await?;
            assert_eq!(names(&r.area(1000))?, [id.clone(), format!("{id}-cert")]);
            r.f.set_answer(Answer::Yes);
            call(&r.a2, "DeleteKey", &(id.as_str(),)).await?;
        }
        // Both orders happened.
        assert!(
            replaced_first > 0 && deleted_first > 0,
            "{replaced_first} {deleted_first}"
        );
        Ok(())
    })
}
