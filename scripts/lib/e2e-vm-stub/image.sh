#!/usr/bin/env bash
# A stub of e2e/vm/image.sh: logs and prints the serial the record must carry.
echo "image" >> "$STUB_LOG"
[ -z "${STUB_FAIL_IMAGE:-}" ] || { echo "stub: image failed" >&2; exit 1; }
printf 'path=/nonexistent/stub.img\nserial=20261105\nsha256=00\n'
