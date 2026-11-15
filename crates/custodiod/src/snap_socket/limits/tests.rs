use super::*;
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

fn ok<T>(r: Result<T, Violation>) -> Result<T, Box<dyn Error>> {
    r.map_err(|v| format!("{v:?}").into())
}

fn header(endian: u8, body: u32, fields: u32) -> Vec<u8> {
    let mut h = vec![endian, 1, 0, 1];
    let (b, f) = if endian == b'l' {
        (body.to_le_bytes(), fields.to_le_bytes())
    } else {
        (body.to_be_bytes(), fields.to_be_bytes())
    };
    h.extend_from_slice(&b);
    h.extend_from_slice(&1_u32.to_le_bytes());
    h.extend_from_slice(&f);
    h
}

fn begun(max: usize) -> Result<Framer, Box<dyn Error>> {
    let mut framer = Framer::new(max);
    let fed = ok(framer.feed(b"\0AUTH ANONYMOUS\r\nBEGIN\r\n"))?;
    assert!(fed.handshake_done);
    Ok(framer)
}

#[test]
fn a_message_of_the_bound_passes_and_one_byte_more_does_not() -> TestResult {
    for endian in *b"lB" {
        // 16 header + 8 padded fields + 8 body = 32.
        let mut whole = header(endian, 8, 5);
        whole.extend(vec![0; 16]);
        let fed = ok(begun(32)?.feed(&whole))?;
        assert_eq!(fed.completed, 1);
        assert!(!fed.began_partial);
        assert_eq!(
            begun(31)?.feed(&header(endian, 8, 5)),
            Err(Violation::TooLarge)
        );
    }
    Ok(())
}

#[test]
fn a_partial_message_is_marked_and_finished_later() -> TestResult {
    let mut framer = begun(64)?;
    let mut msg = header(b'l', 4, 0);
    msg.extend([0; 4]);
    let fed = ok(framer.feed(msg.get(..3).ok_or("short")?))?;
    assert!(fed.began_partial);
    assert_eq!(fed.completed, 0);
    let fed = ok(framer.feed(msg.get(3..10).ok_or("short")?))?;
    assert!(!fed.began_partial);
    let fed = ok(framer.feed(msg.get(10..).ok_or("short")?))?;
    assert_eq!(fed.completed, 1);
    Ok(())
}

#[test]
fn two_messages_in_one_chunk_count_twice() -> TestResult {
    let mut msg = header(b'l', 0, 0);
    msg.extend(header(b'l', 0, 0));
    assert_eq!(ok(begun(64)?.feed(&msg))?.completed, 2);
    Ok(())
}

#[test]
fn a_bad_byte_order_marker_or_an_endless_line_is_refused() -> TestResult {
    assert_eq!(
        begun(64)?.feed(&header(b'x', 0, 0)),
        Err(Violation::BadMessage)
    );
    let mut framer = Framer::new(64);
    assert_eq!(framer.feed(&vec![b'a'; 1024]).map(|f| f.completed), Ok(0));
    assert_eq!(framer.feed(b"a"), Err(Violation::HandshakeLine));
    Ok(())
}

#[test]
fn begin_only_counts_as_a_whole_line() -> TestResult {
    let mut framer = Framer::new(64);
    assert!(!ok(framer.feed(b"XBEGIN\r\n"))?.handshake_done);
    assert!(!ok(framer.feed(b"BEGIN"))?.handshake_done);
    assert!(ok(framer.feed(b"\n"))?.handshake_done);
    Ok(())
}

#[test]
fn a_huge_announced_length_is_too_large_not_an_overflow() -> TestResult {
    assert_eq!(
        begun(4096)?.feed(&header(b'l', u32::MAX, u32::MAX)),
        Err(Violation::TooLarge)
    );
    Ok(())
}

#[test]
fn slots_are_bounded_and_freed() -> TestResult {
    let slots = Slots::default();
    let a = slots.take(2).ok_or("first")?;
    let _b = slots.take(2).ok_or("second")?;
    assert!(slots.take(2).is_none());
    assert_eq!(slots.open(), 2);
    drop(a);
    assert_eq!(slots.open(), 1);
    assert!(slots.take(2).is_some());
    Ok(())
}

#[test]
fn the_rate_limit_writes_k_lines_then_counts_and_reopens() {
    let limit = RateLimit::new(2, Duration::from_secs(10));
    let t0 = Instant::now();
    assert_eq!(limit.check(t0), Line::Write { suppressed: 0 });
    assert_eq!(limit.check(t0), Line::Write { suppressed: 0 });
    assert_eq!(limit.check(t0), Line::Drop);
    assert_eq!(limit.check(t0 + Duration::from_secs(9)), Line::Drop);
    assert_eq!(
        limit.check(t0 + Duration::from_secs(10)),
        Line::Write { suppressed: 2 }
    );
    assert_eq!(
        limit.check(t0 + Duration::from_secs(11)),
        Line::Write { suppressed: 0 }
    );
    assert_eq!(limit.check(t0 + Duration::from_secs(12)), Line::Drop);
}
