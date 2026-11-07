use super::*;
use std::sync::{Mutex, PoisonError};
use zeroize::Zeroize;

const MARKER: &[u8] = b"MARKER-PLAINTEXT-4711";

/// A header-sized credential bound to a TPM with this mask.
fn tpm_credential(mask: u64) -> Vec<u8> {
    let mut bytes = vec![7u8; 48];
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes
}

/// A client that answers from memory and records what it was asked.
struct Memory {
    encrypted: Result<Vec<u8>, CredsError>,
    /// The buffer handed out by `decrypt`, owned by the test.
    key: Mutex<Option<Vec<u8>>>,
    decrypted: Result<(), CredsError>,
    calls: Mutex<Vec<String>>,
}

impl Memory {
    fn new() -> Self {
        Self {
            encrypted: Ok(tpm_credential(0)),
            key: Mutex::new(Some(MARKER.to_vec())),
            decrypted: Ok(()),
            calls: Mutex::default(),
        }
    }
}

impl Credentials for Memory {
    fn encrypt(&self, name: &str, plaintext: &SecretSlice<u8>) -> Result<Vec<u8>, CredsError> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(format!(
                "encrypt {name} {}",
                plaintext.expose_secret().len()
            ));
        self.encrypted.clone()
    }

    fn decrypt(&self, name: &str, credential: &[u8]) -> Result<SecretSlice<u8>, CredsError> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(format!("decrypt {name} {}", credential.len()));
        self.decrypted?;
        let key = self
            .key
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or(CredsError::CannotDecrypt)?;
        Ok(SecretSlice::new(key.into_boxed_slice()))
    }
}

fn plaintext() -> SecretSlice<u8> {
    SecretSlice::new(MARKER.to_vec().into_boxed_slice())
}

#[test]
fn seal_returns_the_credential_and_its_binding() -> Result<(), CredsError> {
    let client = Memory::new();
    let sealed = seal(&client, "k", &plaintext())?;
    assert_eq!(sealed.credential, tpm_credential(0));
    assert_eq!(sealed.binding, Binding::Tpm);
    assert_eq!(
        client
            .calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_slice(),
        [format!("encrypt k {}", MARKER.len())]
    );
    Ok(())
}

#[test]
fn seal_refuses_a_credential_that_names_a_pcr() {
    let mut client = Memory::new();
    client.encrypted = Ok(tpm_credential(0x80));
    assert_eq!(
        seal(&client, "k", &plaintext()),
        Err(CredsError::Refused(HeaderError::PcrBound(0x80)))
    );
}

#[test]
fn seal_refuses_garbage() {
    let mut client = Memory::new();
    client.encrypted = Ok(vec![1, 2, 3]);
    assert_eq!(
        seal(&client, "k", &plaintext()),
        Err(CredsError::Refused(HeaderError::TooShort))
    );
}

#[test]
fn injected_failures_pass_through_unchanged() {
    for error in [
        CredsError::Unavailable,
        CredsError::CannotDecrypt,
        CredsError::BadRequest,
    ] {
        let mut client = Memory::new();
        client.encrypted = Err(error);
        assert_eq!(seal(&client, "k", &plaintext()), Err(error));
        client.decrypted = Err(error);
        let mut used = false;
        let got = with_key(&client, "k", &[1], |_| used = true);
        assert_eq!(got, Err(error));
        assert!(!used, "the key was never produced");
    }
}

#[test]
fn with_key_hands_the_key_to_the_closure_once() -> Result<(), CredsError> {
    let client = Memory::new();
    let got = with_key(&client, "k", &tpm_credential(0), <[u8]>::to_vec)?;
    assert_eq!(got, MARKER);
    assert_eq!(
        client
            .calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len(),
        1
    );
    // The test client had one buffer: a second decrypt fails, nothing is kept by `with_key`.
    assert_eq!(
        with_key(&client, "k", &tpm_credential(0), <[u8]>::len),
        Err(CredsError::CannotDecrypt)
    );
    Ok(())
}

#[test]
fn the_errors_are_distinct_and_carry_no_data() {
    assert_ne!(CredsError::Unavailable, CredsError::CannotDecrypt);
    assert_ne!(
        CredsError::Unavailable.to_string(),
        CredsError::CannotDecrypt.to_string()
    );
    assert!(CredsError::Unavailable.to_string().contains("unavailable"));
    assert!(CredsError::CannotDecrypt.to_string().contains("decrypt"));
    assert!(CredsError::BadRequest.to_string().contains("bad"));
    let refused = CredsError::Refused(HeaderError::PcrBound(0x80)).to_string();
    assert!(refused.contains("refused") && refused.contains("0x80"));
}

#[test]
fn secret_holding_types_do_not_print_the_key() {
    let secret = plaintext();
    let shown = format!("{secret:?}");
    assert!(!shown.contains("MARKER"), "{shown}");
    let sealed = Sealed {
        credential: tpm_credential(0),
        binding: Binding::Tpm,
    };
    assert!(!format!("{sealed:?} {:?}", CredsError::Unavailable).contains("MARKER"));
}

/// Compile-time: what `decrypt` returns zeroizes on drop.
#[test]
fn the_secret_type_zeroizes_on_drop() {
    fn zeroizes<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    zeroizes(&plaintext());
    let mut buffer = MARKER.to_vec();
    buffer.zeroize();
    assert_eq!(buffer.len(), 0);
}
