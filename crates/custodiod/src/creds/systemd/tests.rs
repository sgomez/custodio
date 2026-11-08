use super::*;

fn encoded(data: &[u8]) -> String {
    let mut out = Vec::new();
    base64_encode(&mut out, data);
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn base64_matches_rfc_4648() {
    for (plain, text) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(encoded(plain.as_bytes()), text);
        assert_eq!(
            base64_decode(text.as_bytes()).as_deref(),
            Some(plain.as_bytes())
        );
    }
    // Every sextet value, `+` and `/` included.
    let all: Vec<u8> = (0..=255).collect();
    assert_eq!(base64_decode(encoded(&all).as_bytes()), Some(all));
    assert_eq!(encoded(&[0xFB, 0xFF, 0xBF]), "+/+/");
}

#[test]
fn base64_round_trips_every_short_length() {
    for len in 0..40usize {
        let data: Vec<u8> = (0..len)
            .map(|i| u8::try_from(i * 7 % 256).unwrap_or(0))
            .collect();
        assert_eq!(
            base64_decode(encoded(&data).as_bytes()),
            Some(data),
            "{len}"
        );
    }
}

#[test]
fn base64_ignores_white_space_and_rejects_the_rest() {
    assert_eq!(base64_decode(b"Zm9v\nYmFy\n"), Some(b"foobar".to_vec()));
    assert_eq!(base64_decode(b" Zg==\r\n"), Some(b"f".to_vec()));
    for bad in [
        "A", "Zg=", "Zg===", "Z=g=", "Zm9v*", "====", "Zm9vY", "Zm8=Zm8=",
    ] {
        assert_eq!(base64_decode(bad.as_bytes()), None, "{bad}");
    }
    // No padding is accepted when the length allows it.
    assert_eq!(base64_decode(b"Zm8"), Some(b"fo".to_vec()));
    assert_eq!(base64_decode(b"Zg"), Some(b"f".to_vec()));
}

#[test]
fn names_are_checked_before_they_reach_json_or_an_argument() {
    for ok in ["k", "key-1", "A.b_c", &"x".repeat(255)] {
        assert!(valid_name(ok), "{ok}");
    }
    for bad in [
        "",
        "a b",
        "a\"b",
        "a/b",
        "a\\b",
        "é",
        "a=b",
        "a\n",
        &"x".repeat(256),
    ] {
        assert!(!valid_name(bad), "{bad}");
    }
}

#[test]
fn the_request_is_one_json_line_ended_by_nul() {
    let line = request("Encrypt", "k", "data", b"foo");
    assert_eq!(
        line.as_slice(),
        br#"{"method":"io.systemd.Credentials.Encrypt","parameters":{"name":"k","data":"Zm9v","scope":"user"}}"#
            .iter()
            .chain(b"\0")
            .copied()
            .collect::<Vec<u8>>()
    );
    let line = request("Decrypt", "n", "blob", b"");
    assert!(line.starts_with(br#"{"method":"io.systemd.Credentials.Decrypt""#));
    assert!(line.windows(10).any(|w| w == br#""blob":"","#));
    assert!(!line.windows(7).any(|w| w == b"withKey"));
}

#[test]
fn replies_are_read_by_field() {
    let ok = br#"{"parameters":{"blob":"VbntHQ=="}}"#;
    assert_eq!(field(ok, "blob"), Some(&b"VbntHQ=="[..]));
    assert_eq!(field(ok, "data"), None);
    assert_eq!(error_name(ok), None);
    let err = br#"{"error":"io.systemd.Credentials.BadFormat","parameters":{}}"#;
    assert_eq!(
        error_name(err),
        Some(&b"io.systemd.Credentials.BadFormat"[..])
    );
    assert_eq!(field(err, "blob"), None);
    // An unterminated value is not a value.
    assert_eq!(field(br#"{"blob":"abc"#, "blob"), None);
    assert_eq!(field(br#"{"blob":""}"#, "blob"), Some(&b""[..]));
}

#[test]
fn the_decrypted_reply_is_wiped_in_place() -> Result<(), &'static str> {
    let mut reply = br#"{"parameters":{"data":"Zm9vYmFy"}}"#.to_vec();
    let length = reply.len();
    let secret = take_data(&mut reply).ok_or("no data")?;
    assert_eq!(secret.expose_secret(), b"foobar");
    assert!(reply.iter().all(|&b| b == 0), "the reply still holds data");
    assert_eq!(reply.len(), length, "wiped in place, same length");
    Ok(())
}

#[test]
fn a_bad_reply_is_wiped_too() {
    let mut reply = br#"{"parameters":{"data":"!!!!"}}"#.to_vec();
    assert!(take_data(&mut reply).is_none());
    assert!(reply.iter().all(|&b| b == 0));
    let mut reply = br#"{"parameters":{}}"#.to_vec();
    assert!(take_data(&mut reply).is_none());
}

#[test]
fn bad_names_never_reach_the_service() {
    let client = SystemdCreds::new("/nonexistent".into());
    let secret = SecretSlice::new(Box::from(&b"x"[..]));
    assert_eq!(
        client.encrypt("a b", &secret).err(),
        Some(CredsError::BadRequest)
    );
    assert_eq!(
        client.decrypt("a b", &[0; 64]).err(),
        Some(CredsError::BadRequest)
    );
    // A valid name gets as far as the missing socket.
    assert_eq!(
        client.encrypt("ab", &secret).err(),
        Some(CredsError::Unavailable)
    );
}

#[test]
fn the_system_client_uses_the_system_socket() {
    assert_eq!(SystemdCreds::system().socket, PathBuf::from(SOCKET));
}

/// A header of the F153 layout: 48 bytes of id and sizes, then the TPM section starts with the PCR mask.
fn tpm_header(mask: u64) -> Vec<u8> {
    let mut credential = vec![7u8; 48];
    credential.extend_from_slice(&mask.to_le_bytes());
    credential.extend_from_slice(&[0; 8]);
    credential
}

/// A header with the id of the scoped host key.
fn host_header() -> Vec<u8> {
    let mut credential = header::HOST_SCOPED_ID.to_vec();
    credential.extend_from_slice(&[0; 40]);
    credential
}

#[test]
fn a_credential_goes_to_varlink_whatever_its_binding() {
    // Unusable socket: unavailable, never a failed decryption, and nothing else is tried.
    let client = SystemdCreds::new("/nonexistent".into());
    assert_eq!(
        client.decrypt("k", &tpm_header(0)).err(),
        Some(CredsError::Unavailable)
    );
    // A header that the guard refuses never gets to the socket.
    assert_eq!(
        client.decrypt("k", &[1, 2]).err(),
        Some(CredsError::CannotDecrypt)
    );
}

/// What the client sent, and the reply it got, for one call against a server that answers `reply`.
fn exchange(reply: &[u8], call: impl FnOnce(&SystemdCreds)) -> std::io::Result<Vec<u8>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("sock");
    let listener = std::os::unix::net::UnixListener::bind(&path)?;
    let reply = reply.to_vec();
    let handle = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let (mut stream, _) = listener.accept()?;
        let mut sent = Vec::new();
        let mut chunk = [0u8; 4096];
        while !sent.ends_with(b"\0") {
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            sent.extend_from_slice(chunk.get(..n).unwrap_or_default());
        }
        stream.write_all(&reply)?;
        Ok(sent)
    });
    call(&SystemdCreds::new(path.clone()));
    // A client that never connected leaves the server in `accept`: wake it so the join returns.
    let _ = std::os::unix::net::UnixStream::connect(&path);
    handle
        .join()
        .map_err(|_| std::io::Error::other("server panicked"))?
}

#[test]
fn encrypt_asks_varlink_for_the_user_scope_without_a_key_choice() -> std::io::Result<()> {
    let secret = SecretSlice::new(Box::from(&b"foo"[..]));
    let mut blob = None;
    let sent = exchange(b"{\"parameters\":{\"blob\":\"Zm9vYmFy\"}}\0", |c| {
        blob = c.encrypt("k", &secret).ok();
    })?;
    assert_eq!(blob.as_deref(), Some(&b"foobar"[..]));
    let sent = String::from_utf8_lossy(&sent);
    assert!(
        sent.contains(r#""method":"io.systemd.Credentials.Encrypt""#),
        "{sent}"
    );
    assert!(sent.contains(r#""scope":"user""#), "{sent}");
    assert!(sent.contains(r#""data":"Zm9v""#), "{sent}");
    assert!(!sent.contains("withKey"), "{sent}");
    Ok(())
}

#[test]
fn decrypt_asks_varlink_once_for_a_tpm_and_for_a_host_header() -> std::io::Result<()> {
    for credential in [tpm_header(0), host_header()] {
        let mut secret = None;
        let sent = exchange(b"{\"parameters\":{\"data\":\"Zm9v\"}}\0", |c| {
            secret = c.decrypt("k", &credential).ok();
        })?;
        assert_eq!(
            secret.as_ref().map(|s| s.expose_secret().to_vec()),
            Some(b"foo".to_vec())
        );
        let sent = String::from_utf8_lossy(&sent);
        assert_eq!(
            sent.matches("io.systemd.Credentials.Decrypt").count(),
            1,
            "{sent}"
        );
        assert!(sent.contains(r#""scope":"user""#), "{sent}");
    }
    Ok(())
}

/// A socket that answers the first connection with these pieces, a pause between them so that the
/// client reads them one by one, and then closes.
fn serve(
    pieces: Vec<Vec<u8>>,
) -> std::io::Result<(tempfile::TempDir, SystemdCreds, std::thread::JoinHandle<()>)> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("sock");
    let listener = std::os::unix::net::UnixListener::bind(&path)?;
    let handle = std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut request = [0u8; 64];
        let _ = stream.read(&mut request);
        for piece in pieces {
            let _ = stream.write_all(&piece);
            std::thread::sleep(Duration::from_millis(25));
        }
    });
    let client = SystemdCreds::new(path);
    Ok((dir, client, handle))
}

fn ask(pieces: Vec<Vec<u8>>) -> Result<Vec<u8>, CredsError> {
    let (dir, client, handle) = serve(pieces).map_err(|_| CredsError::BadRequest)?;
    let got = client.varlink(b"{}\0").map(|reply| reply.to_vec());
    // A client that never connected leaves the server in `accept`: wake it so the join returns.
    let _ = std::os::unix::net::UnixStream::connect(dir.path().join("sock"));
    let _ = handle.join();
    got
}

fn full_pieces(count: usize) -> Vec<Vec<u8>> {
    vec![vec![b'a'; 4096]; count]
}

#[test]
fn a_reply_may_come_in_pieces_and_stops_at_the_nul() {
    let mut pieces = full_pieces(5);
    pieces.push(b"bb\0trailing".to_vec());
    let got = ask(pieces).unwrap_or_default();
    assert_eq!(got.len(), 5 * 4096 + 2);
    assert!(got.ends_with(b"aabb"));
    assert_eq!(ask(vec![b"abc\0def".to_vec()]), Ok(b"abc".to_vec()));
    assert_eq!(ask(vec![b"\0".to_vec()]), Ok(Vec::new()));
}

#[test]
fn a_reply_of_the_largest_size_is_taken_and_one_more_piece_is_not() {
    let mut pieces = full_pieces(MAX_REPLY / 4096);
    pieces.push(b"\0".to_vec());
    assert_eq!(ask(pieces).map(|r| r.len()), Ok(MAX_REPLY));
    let mut pieces = full_pieces(MAX_REPLY / 4096 + 1);
    pieces.push(b"\0".to_vec());
    assert_eq!(ask(pieces), Err(CredsError::Unavailable));
    // Far over, the NUL far away: still refused, not read to the end.
    let mut pieces = full_pieces(MAX_REPLY / 4096 + 3);
    pieces.push(b"\0".to_vec());
    assert_eq!(ask(pieces), Err(CredsError::Unavailable));
}

#[test]
fn a_reply_that_ends_without_a_nul_is_unavailable() {
    assert_eq!(ask(vec![b"abc".to_vec()]), Err(CredsError::Unavailable));
    assert_eq!(ask(Vec::new()), Err(CredsError::Unavailable));
}

#[test]
fn the_largest_reply_is_64_kib() {
    assert_eq!(MAX_REPLY, 65536);
}

/// A reader that is interrupted by a signal before each piece.
struct Interrupted(Vec<&'static [u8]>, bool);

impl Read for Interrupted {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.1 = !self.1;
        if self.1 {
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        let piece = self.0.remove(0);
        let dst = buf
            .get_mut(..piece.len())
            .ok_or(std::io::ErrorKind::InvalidInput)?;
        dst.copy_from_slice(piece);
        Ok(piece.len())
    }
}

#[test]
fn a_read_cut_short_by_a_signal_is_repeated() {
    let got = read_reply(&mut Interrupted(vec![b"ab", b"c\0"], false)).map(|r| r.to_vec());
    assert_eq!(got, Ok(b"abc".to_vec()));
}

#[test]
fn another_read_error_is_unavailable_at_once() {
    struct Broken(usize);
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            self.0 += 1;
            Err(std::io::ErrorKind::ConnectionReset.into())
        }
    }
    let mut reader = Broken(0);
    assert_eq!(
        read_reply(&mut reader).map(|r| r.to_vec()),
        Err(CredsError::Unavailable)
    );
    assert_eq!(reader.0, 1);
}
