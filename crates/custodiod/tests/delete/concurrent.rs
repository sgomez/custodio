//! Deletes at the same time: two deletes of one id, and a sign that is in progress.

use std::future::Future;
use std::sync::atomic::Ordering;
use std::task::Poll;

use custodio_client::ERROR_NO_SUCH_KEY;
use rsa::pkcs8::DecodePrivateKey;
use zbus::{Connection, block_on};

use super::bus::{Answer, TestResult, error_name, sign};
use super::common::{CKM_RSA_PKCS, EC_P12, PASSWORD, RSA_P12, digest, digest_info};
use super::{NONE, Rig, delete, names};

/// Polls both futures from one task until both are done. After about 300 ms of polling (the time
/// a second call needs to show it is waiting) `release` runs once.
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
fn concurrent_deletes_run_one_at_a_time() -> TestResult {
    block_on(async {
        let r = Rig::start(Answer::Yes, 1000, 1001).await?;
        for round in 0..20_usize {
            let id = format!("r{round}");
            r.import(r.a(), &id, EC_P12, Answer::Yes).await?;
            // The first delete is held in polkit; the second must wait for it, not reach polkit.
            r.f.hold.store(usize::MAX, Ordering::SeqCst);
            let release = &r.f.hold;
            let (x, y) = join2(delete(r.a(), &id), delete(&r.a2, &id), || {
                release.store(0, Ordering::SeqCst);
            })
            .await;
            assert_eq!(r.f.asked().len(), 1, "round {round}");
            let mut got = [x, y];
            got.sort();
            assert_eq!(
                got,
                [Ok(()), Err(ERROR_NO_SUCH_KEY.to_owned())],
                "round {round}"
            );
            assert!(names(&r.area(1000))?.is_empty(), "round {round}");
        }
        Ok(())
    })
}

fn rsa_public() -> Result<rsa::RsaPublicKey, Box<dyn std::error::Error>> {
    let key =
        custodiod::import::parse_p12(RSA_P12, &secrecy::SecretString::from(PASSWORD.to_owned()))?
            .key;
    Ok(
        rsa::RsaPrivateKey::from_pkcs8_der(secrecy::ExposeSecret::expose_secret(&key))?
            .to_public_key(),
    )
}

async fn sign_rsa(c: &Connection) -> Result<Vec<u8>, String> {
    sign(c, "k", CKM_RSA_PKCS, &digest_info())
        .await
        .map_err(|e| error_name(&e))
}

#[test]
fn sign_during_delete_completes_with_the_key() -> TestResult {
    block_on(async {
        let public = rsa_public()?;
        // Both orders of arrival at polkit: the double holds the first request for the second.
        for delete_first in [false, true] {
            let r = Rig::start(Answer::Yes, 1000, 1001).await?;
            r.import(r.a(), "k", RSA_P12, Answer::Yes).await?;
            r.f.hold.store(2, Ordering::SeqCst);
            let (sig, del) = if delete_first {
                let (d, s) = join2(delete(&r.a2, "k"), sign_rsa(r.a()), || ()).await;
                (s, d)
            } else {
                join2(sign_rsa(r.a()), delete(&r.a2, "k"), || ()).await
            };
            // The sign had the key before the delete could remove it.
            let sig = sig.map_err(|e| format!("sign failed: {e}"))?;
            public.verify(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &digest(), &sig)?;
            assert_eq!(del, Ok(()));
            assert_eq!(r.f.asked().len(), 2);
            r.f.hold.store(0, Ordering::SeqCst);
            assert_eq!(sign_rsa(r.a()).await, Err(ERROR_NO_SUCH_KEY.to_owned()));
            assert_eq!(names(&r.area(1000))?, NONE);
        }
        Ok(())
    })
}
