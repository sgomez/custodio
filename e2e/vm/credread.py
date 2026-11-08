#!/usr/bin/env python3
"""Reads a stored systemd-creds credential and prints its key identifier and PCR mask (F157).

Written from the header and identifier tables of docs/findings/F153.md; it shares nothing with the service.
Run it as `python3 -I credread.py FILE [--expect-tpm-bound --systemd-version N]`.

FILE is the base64 text `systemd-creds encrypt` writes, or the raw binary. Rule: a file whose bytes are all
printable ASCII or whitespace is text and must strictly decode as base64 (else malformed); any other file is raw.

Output: `<name>` for a key without TPM, `<name> mask 0x<hex>` for a TPM key. Exit 0 on success, 1 when the file is
refused (one line on stderr naming the reason), 2 on a usage error.
"""
import base64
import binascii
import string
import struct
import sys

# F153 identifier table: 16 bytes at offset 0.
IDS = {
    "5a1c6a86df9d4096b1d5a65e0862f19a": "host",
    "55b9ed1d38594d43a8319d2ebb332ac6": "host-scoped",
    "0c7cc07b117645919c4b0bea08bc20fe": "tpm2",
    "faf7eb9341e3412ca1a436f95a29362f": "tpm2-with-public-key",
    "93a894094874449090caf2fc93cab553": "host+tpm2",
    "ef4ac13679a9480ea7db68897f9f165d": "host+tpm2-scoped",
    "af4950a849134eb1a73846304ff30c05": "host+tpm2-with-public-key",
    "adbc4ca3efb64201ba881b6f2e4095ea": "host+tpm2-with-public-key-scoped",
    "058469daf6f54324800549da0f8ea2fb": "null",
}
TPM = {"tpm2", "tpm2-with-public-key", "host+tpm2", "host+tpm2-scoped", "host+tpm2-with-public-key",
       "host+tpm2-with-public-key-scoped"}
PK = {"tpm2-with-public-key", "host+tpm2-with-public-key", "host+tpm2-with-public-key-scoped"}
SCOPED = {"host-scoped", "host+tpm2-scoped", "host+tpm2-with-public-key-scoped"}
SUPPORTED_VERSIONS = ("257", "259")


class Refused(Exception):
    pass


def malformed(why):
    return Refused("malformed header: " + why)


def align8(n):
    return (n + 7) & ~7


def decode_file(data):
    text_bytes = set(string.printable.encode())
    if all(b in text_bytes for b in data):
        try:
            return base64.b64decode(b"".join(data.split()), validate=True)
        except (binascii.Error, ValueError):
            raise malformed("text that is not base64")
    return data


def need(data, end, what):
    if end > len(data):
        raise malformed("%s needs %d bytes, the file has %d" % (what, end, len(data)))


def parse(data):
    """Returns (name, mask or None, hexid)."""
    need(data, 32, "key id and sizes")
    hexid = data[:16].hex()
    name = IDS.get(hexid)
    iv_size = struct.unpack_from("<I", data, 24)[0]
    off = align8(32 + iv_size)
    need(data, off, "iv (iv_size %d)" % iv_size)
    if name is None:
        return None, None, hexid
    mask = None
    if name in TPM:
        need(data, off + 20, "TPM section")
        mask, _bank, _alg, blob, policy = struct.unpack_from("<QHHII", data, off)
        off += align8(20 + blob + policy)
        need(data, off, "TPM blob and policy hash")
        if name in PK:
            need(data, off + 12, "public key section")
            pk_size = struct.unpack_from("<I", data, off + 8)[0]
            off += align8(12 + pk_size)
            need(data, off, "public key")
    if name in SCOPED:
        need(data, off + 8, "scoped header flags")
    return name, mask, hexid


def judge(name, mask, hexid, version):
    if name is None:
        raise Refused("unknown key identifier " + hexid)
    if name == "null":
        raise Refused("null key: no confidentiality")
    if name in ("host", "host-scoped"):
        raise Refused("host-only key (%s): not bound to the TPM" % name)
    if name == "tpm2":
        raise Refused("TPM-only key (tpm2): not user-scoped host plus TPM")
    if name != "host+tpm2-scoped":
        raise Refused("key %s is not the user-scoped host plus TPM identifier" % name)
    if mask != 0:
        raise Refused("PCR mask 0x%x is not 0" % mask)


def main(argv):
    path = None
    expect = False
    version = None
    args = list(argv)
    while args:
        a = args.pop(0)
        if a == "--expect-tpm-bound":
            expect = True
        elif a == "--systemd-version" and args:
            version = args.pop(0)
        elif path is None and not a.startswith("--"):
            path = a
        else:
            print("credread: usage: credread.py FILE [--expect-tpm-bound --systemd-version N]", file=sys.stderr)
            return 2
    if path is None or (expect and version is None):
        print("credread: usage: credread.py FILE [--expect-tpm-bound --systemd-version N]"
              " (--expect-tpm-bound needs --systemd-version)", file=sys.stderr)
        return 2
    if expect and version not in SUPPORTED_VERSIONS:
        print("credread: unsupported systemd version %s (known: %s)" % (version, ", ".join(SUPPORTED_VERSIONS)),
              file=sys.stderr)
        return 1
    try:
        with open(path, "rb") as f:
            raw = f.read()
        name, mask, hexid = parse(decode_file(raw))
        if name is None:
            print("unknown " + hexid)
        elif mask is None:
            print(name)
        else:
            print("%s mask 0x%x" % (name, mask))
        if expect:
            judge(name, mask, hexid, version)
        elif name is None:
            raise Refused("unknown key identifier " + hexid)
    except Refused as e:
        print("credread: " + str(e), file=sys.stderr)
        return 1
    except OSError as e:
        print("credread: cannot read %s: %s" % (path, e.strerror), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
