"""Test-only OpenPGP Ed25519 key and detached-signature maker (stdlib only), for scripts/test-vm-image.sh.

The dev container has `gpg` but no `gpg-agent`, so `gpg` cannot make a key or sign; `gpgv` only verifies. This writes what
`gpgv --keyring` needs: a public key file (one v4 EdDSA public-key packet) and binary detached signatures (RFC 4880 / 9580).
The keys come from fixed seeds and are throwaway: they sign nothing real.

  openpgp_ed25519.py pub SEED OUT_KEYRING
  openpgp_ed25519.py sign SEED FILE OUT_SIG
"""
import hashlib
import struct
import sys

# --- Ed25519, RFC 8032 section 6 (reference implementation; slow but enough for a few signatures)
P = 2**255 - 19
Q = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)


def _inv(x):
    return pow(x, P - 2, P)


def _xrecover(y):
    xx = (y * y - 1) * _inv(D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = x * I % P
    return P - x if x % 2 != 0 else x


BY = 4 * _inv(5) % P
B = (_xrecover(BY), BY)


def _add(p, q):
    x1, y1 = p
    x2, y2 = q
    t = D * x1 * x2 * y1 * y2
    return ((x1 * y2 + x2 * y1) * _inv(1 + t) % P, (y1 * y2 + x1 * x2) * _inv(1 - t) % P)


def _mul(p, e):
    r = (0, 1)
    while e:
        if e & 1:
            r = _add(r, p)
        p = _add(p, p)
        e >>= 1
    return r


def _enc(p):
    x, y = p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _h(m):
    return hashlib.sha512(m).digest()


def _secret(seed):
    h = _h(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public(seed):
    a, _ = _secret(seed)
    return _enc(_mul(B, a))


def ed_sign(seed, msg):
    a, prefix = _secret(seed)
    pub = _enc(_mul(B, a))
    r = int.from_bytes(_h(prefix + msg), "little") % Q
    rr = _enc(_mul(B, r))
    k = int.from_bytes(_h(rr + pub + msg), "little") % Q
    return rr + ((r + k * a) % Q).to_bytes(32, "little")


# --- OpenPGP packets
CREATED = 1700000000
OID = bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01])


def _mpi(b):
    b = b.lstrip(b"\0")
    bits = (len(b) - 1) * 8 + b[0].bit_length() if b else 0
    return struct.pack(">H", bits) + b


def _packet(tag, body):
    return bytes([0xC0 | tag]) + (bytes([len(body)]) if len(body) < 192 else bytes([0xFF]) + struct.pack(">I", len(body))) + body


def _pubbody(seed):
    return b"\x04" + struct.pack(">I", CREATED) + b"\x16" + bytes([len(OID)]) + OID + _mpi(b"\x40" + public(seed))


def _fpr(seed):
    body = _pubbody(seed)
    return hashlib.sha1(b"\x99" + struct.pack(">H", len(body)) + body).digest()


def keyring(seed):
    """Public key, user id and self-signature: gpgv ignores a bare key packet."""
    body = _pubbody(seed)
    uid = b"test key <test@example.invalid>"
    fpr = _fpr(seed)
    hashed = bytes([5, 2]) + struct.pack(">I", CREATED) + bytes([2, 27, 3]) + bytes([22, 33, 4]) + fpr
    head = b"\x04\x13\x16\x08" + struct.pack(">H", len(hashed)) + hashed
    signed = b"\x99" + struct.pack(">H", len(body)) + body + b"\xb4" + struct.pack(">I", len(uid)) + uid
    digest = hashlib.sha256(signed + head + b"\x04\xff" + struct.pack(">I", len(head))).digest()
    unhashed = bytes([9, 16]) + fpr[-8:]
    sig = ed_sign(seed, digest)
    sbody = head + struct.pack(">H", len(unhashed)) + unhashed + digest[:2] + _mpi(sig[:32]) + _mpi(sig[32:])
    return _packet(6, body) + _packet(13, uid) + _packet(2, sbody)


def detached(seed, data):
    fpr = _fpr(seed)
    hashed = bytes([5, 2]) + struct.pack(">I", CREATED + 1) + bytes([22, 33, 4]) + fpr
    head = b"\x04\x00\x16\x08" + struct.pack(">H", len(hashed)) + hashed
    digest = hashlib.sha256(data + head + b"\x04\xff" + struct.pack(">I", len(head))).digest()
    unhashed = bytes([9, 16]) + fpr[-8:]
    sig = ed_sign(seed, digest)
    body = head + struct.pack(">H", len(unhashed)) + unhashed + digest[:2] + _mpi(sig[:32]) + _mpi(sig[32:])
    return _packet(2, body)


def main(argv):
    if len(argv) == 4 and argv[1] == "pub":
        open(argv[3], "wb").write(keyring(argv[2].encode().ljust(32, b"\0")[:32]))
    elif len(argv) == 5 and argv[1] == "sign":
        open(argv[4], "wb").write(detached(argv[2].encode().ljust(32, b"\0")[:32], open(argv[3], "rb").read()))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
