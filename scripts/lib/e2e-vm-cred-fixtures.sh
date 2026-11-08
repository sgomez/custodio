# shellcheck shell=bash
# Sourced by the F161 self-tests: synthetic stored records and credentials (header layout of docs/findings/F153.md, record layout of crates/custodiod/src/store/record.rs).
rec() { # DIR ID KINDTAG CREDFILE: a record file as record.rs writes it, in DIR/1000/
    mkdir -p "$1/1000"
    python3 -I - "$1/1000/$2.key" "$2" "$3" "$4" << 'PY'
import sys
path, key_id, tag, cred = sys.argv[1], sys.argv[2], int(sys.argv[3]), open(sys.argv[4], "rb").read()
out = b"CUSTODIO" + bytes([1, tag]) + (1000).to_bytes(4, "big") + bytes([len(key_id)]) + key_id.encode()
out += (3).to_bytes(4, "big") + b"crt" + len(cred).to_bytes(4, "big") + cred
open(path, "wb").write(out)
PY
}
cred() { # OUT IDHEX MASK: a synthetic credential with the header of F153 (host+tpm2 scoped when the id says so)
    python3 -I - "$1" "$2" "$3" << 'PY'
import struct, sys
out, idhex, mask = sys.argv[1], sys.argv[2], int(sys.argv[3], 0)
b = bytes.fromhex(idhex) + struct.pack("<IIII", 32, 1, 12, 16) + bytes(12) + bytes(4)
b += struct.pack("<QHHII", mask, 0x000b, 0x0023, 240, 32) + bytes(240 + 32)
b = b[:344] if len(b) >= 344 else b + bytes(344 - len(b))
b += struct.pack("<Q", 7) + bytes(64)
open(out, "wb").write(b)
PY
}
