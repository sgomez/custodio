#!/usr/bin/env bash
# The checks of the replace-* and delete-* judgements (rd-lib.sh) on made-up evidence, good and bad. Container-free; the guest runs it first.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/rd-lib.sh
source "$here/rd-lib.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "rd-selftest: $*" >&2; fail=1; }
expect_ok() { local n=$1 out; shift; out=$("$@"); [ -z "$out" ] || bad "$n: problems on good evidence: $out"; }
expect_bad() { local n=$1 out; shift; out=$("$@"); [ -n "$out" ] || bad "$n: no problem on bad evidence"; }

printf 'old' > "$tmp/old"; printf 'new' > "$tmp/new"; cp "$tmp/new" "$tmp/new2"; : > "$tmp/empty"
expect_ok sha-same rd_sha_problems l "$tmp/new" "$tmp/new2"
expect_bad sha-old-for-new rd_sha_problems l "$tmp/old" "$tmp/new"
expect_bad sha-empty-both rd_sha_problems l "$tmp/empty" "$tmp/empty"
expect_bad sha-missing rd_sha_problems l "$tmp/none" "$tmp/new"
expect_ok not-sha rd_not_sha_problems l "$tmp/old" "$tmp/new"
expect_bad not-sha-same rd_not_sha_problems l "$tmp/new" "$tmp/new2"
expect_bad not-sha-empty rd_not_sha_problems l "$tmp/empty" "$tmp/new"

cat > "$tmp/list" <<'LIST'
id: a
  type: rsa2048
  subject: CN=f93-new
  valid until: x
id: b
  type: rsa2048
  subject: CN=f93-old
  valid until: x
LIST
expect_ok subject rd_subject_problems "$tmp/list" a f93-new f93-old
expect_bad subject-old rd_subject_problems "$tmp/list" b f93-new f93-old
expect_bad subject-both rd_subject_problems "$tmp/list" a f93-new f93-new
expect_bad subject-lacks rd_subject_problems "$tmp/list" a f93-zzz f93-old
expect_bad subject-no-id rd_subject_problems "$tmp/list" c f93-new f93-old

cat > "$tmp/slots" <<'SLOTS'
Available slots:
Slot 0 (0x0): Custodio token
  token label        : keep
Slot 1 (0x1): Custodio token
  token label        : gone-not
SLOTS
expect_ok token rd_token_problems "$tmp/slots" +keep -gone
expect_bad token-present rd_token_problems "$tmp/slots" +keep -gone-not
expect_bad token-missing rd_token_problems "$tmp/slots" +other
expect_bad token-substring rd_token_problems "$tmp/slots" +gone
expect_bad token-no-control rd_token_problems "$tmp/slots" -gone
echo "Available slots:" > "$tmp/noload"
expect_bad token-module-failed rd_token_problems "$tmp/noload" +keep -gone
exit "$fail"
