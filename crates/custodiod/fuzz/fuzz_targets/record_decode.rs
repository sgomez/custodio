#![no_main]

use custodiod::store::Record;
use libfuzzer_sys::fuzz_target;

// A stored record is read from disk: an accepted one re-encodes, and the bytes decode to the same owner, id, kind and
// certificate. Nothing panics.
fuzz_target!(|data: &[u8]| {
    if let Ok(record) = Record::decode(data) {
        let bytes = record.encode().expect("an accepted record encodes");
        let again = Record::decode(&bytes).expect("an encoded record decodes");
        assert_eq!(again.owner(), record.owner());
        assert_eq!(again.id(), record.id());
        assert_eq!(again.kind(), record.kind());
        assert_eq!(again.certificate(), record.certificate());
        assert!(again == record);
    }
});
