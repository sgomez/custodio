#!/usr/bin/env bash
# The checks of the cli-* judgements (cli-lib.sh) on made-up evidence, good and bad. Container-free; the guest runs it first.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/cli-lib.sh
source "$here/cli-lib.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "cli-selftest: $*" >&2; fail=1; }
expect_ok() { local n=$1 out; shift; out=$("$@"); [ -z "$out" ] || bad "$n: problems on good evidence: $out"; }
expect_bad() { local n=$1 out; shift; out=$("$@"); [ -n "$out" ] || bad "$n: no problem on bad evidence"; }
w() { printf '%s\n' "${@:2}" > "$tmp/$1"; }

# the list
w list 'id: a' '  type: rsa2048' '  subject: CN=f97-rsa' '  valid until: 2026-12-02T10:00:00Z' 'id: b' '  type: ecdsa-p256' '  subject: CN=f97-ec' '  valid until: 2026-12-17T10:00:00Z'
expect_ok block cli_list_block_problems "$tmp/list" a rsa2048 CN=f97-rsa 2026-12-02T10:00:00Z
expect_ok block-ec cli_list_block_problems "$tmp/list" b ecdsa-p256 CN=f97-ec 2026-12-17T10:00:00Z
expect_bad block-type-of-other-key cli_list_block_problems "$tmp/list" a ecdsa-p256 CN=f97-rsa 2026-12-02T10:00:00Z
expect_bad block-subject cli_list_block_problems "$tmp/list" a rsa2048 CN=f97-ec 2026-12-02T10:00:00Z
expect_bad block-end cli_list_block_problems "$tmp/list" a rsa2048 CN=f97-rsa 2026-12-03T10:00:00Z
expect_bad block-no-id cli_list_block_problems "$tmp/list" c rsa2048 CN=f97-rsa 2026-12-02T10:00:00Z
w nosubject 'id: a' '  type: rsa2048' '  valid until: 2026-12-02T10:00:00Z'
expect_bad block-lacks-subject cli_list_block_problems "$tmp/nosubject" a rsa2048 CN=f97-rsa 2026-12-02T10:00:00Z
w notype 'id: a' '  subject: CN=f97-rsa' '  valid until: 2026-12-02T10:00:00Z'
expect_bad block-lacks-type cli_list_block_problems "$tmp/notype" a rsa2048 CN=f97-rsa 2026-12-02T10:00:00Z
w noend 'id: a' '  type: rsa2048' '  subject: CN=f97-rsa'
expect_bad block-lacks-end cli_list_block_problems "$tmp/noend" a rsa2048 CN=f97-rsa 2026-12-02T10:00:00Z
expect_ok only cli_list_only_problems "$tmp/list" a b
expect_bad only-foreign cli_list_only_problems "$tmp/list" a
expect_bad only-missing cli_list_only_problems "$tmp/list" a b c
w none 'You have no keys in the custodio service.'
expect_ok none cli_none_problems "$tmp/none" 0
expect_bad none-exit cli_none_problems "$tmp/none" 1
expect_bad none-with-keys cli_none_problems "$tmp/list" 0
w nonenothing 'something else'
w both 'You have no keys in the custodio service.' 'id: a' '  type: rsa2048'
expect_bad none-sentence-and-keys cli_none_problems "$tmp/both" 0
expect_bad none-no-sentence cli_none_problems "$tmp/nonenothing" 0
expect_ok has-keys cli_has_keys_problems "$tmp/list"
expect_bad has-keys-none cli_has_keys_problems "$tmp/none"
expect_bad has-keys-sentence-and-keys cli_has_keys_problems "$tmp/both"
expect_bad has-keys-nothing cli_has_keys_problems "$tmp/nonenothing"

# the confirmation and the prompts of pkttyagent
w q 'Delete key '"'"'a'"'"'? It cannot be recovered. Type yes to delete it, anything else to cancel: '
printf 'expect\trecovered\trequests=0\n' > "$tmp/ev"
printf 'expect\trecovered\trequests=1\n' > "$tmp/ev-late"
printf 'expect\trecovered\trequests=-\n' > "$tmp/ev-noagent"
: > "$tmp/ev-empty"
expect_ok confirm cli_confirm_problems "$tmp/q" "$tmp/ev"
expect_ok confirm-no-agent cli_confirm_problems "$tmp/q" "$tmp/ev-noagent"
expect_bad confirm-polkit-first cli_confirm_problems "$tmp/q" "$tmp/ev-late"
expect_bad confirm-never-seen cli_confirm_problems "$tmp/q" "$tmp/ev-empty"
expect_bad confirm-not-in-output cli_confirm_problems "$tmp/none" "$tmp/ev"
w pk '==== AUTHENTICATING FOR com.rfirma.custodio.import-certificate ====' 'Authentication is required to import a certificate' 'Authenticating as: Carol (carol)' 'Password: '
printf 'expect\tPassword: \trequests=-\n' > "$tmp/ev-pw"
expect_ok prompt cli_agent_prompt_problems "$tmp/pk" "$tmp/ev-pw" com.rfirma.custodio.import-certificate carol
expect_bad prompt-other-action cli_agent_prompt_problems "$tmp/pk" "$tmp/ev-pw" com.rfirma.custodio.delete-certificate carol
expect_bad prompt-other-account cli_agent_prompt_problems "$tmp/pk" "$tmp/ev-pw" com.rfirma.custodio.import-certificate dave
expect_bad prompt-no-password-asked cli_agent_prompt_problems "$tmp/pk" "$tmp/ev-empty" com.rfirma.custodio.import-certificate carol
expect_bad prompt-no-header cli_agent_prompt_problems "$tmp/none" "$tmp/ev-pw" com.rfirma.custodio.import-certificate carol
printf 'missing\tPassword: \trequests=-\n' > "$tmp/ev-missing"
expect_ok events cli_events_problems "$tmp/ev"
expect_bad events-missing cli_events_problems "$tmp/ev-missing"
expect_bad events-no-file cli_events_problems "$tmp/nofile"

w pk-ok '==== AUTHENTICATING FOR x ====' '==== AUTHENTICATION COMPLETE ===='
w pk-both '==== AUTHENTICATION FAILED ====' '==== AUTHENTICATION COMPLETE ===='
w pk-bad '==== AUTHENTICATING FOR x ====' '==== AUTHENTICATION FAILED ===='
expect_ok outcome-complete cli_agent_outcome_problems "$tmp/pk-ok" complete
expect_ok outcome-failed cli_agent_outcome_problems "$tmp/pk-bad" failed
expect_bad outcome-complete-got-failed cli_agent_outcome_problems "$tmp/pk-bad" complete
expect_bad outcome-failed-got-complete cli_agent_outcome_problems "$tmp/pk-ok" failed
expect_bad outcome-failed-got-nothing cli_agent_outcome_problems "$tmp/none" failed
expect_bad outcome-failed-got-both cli_agent_outcome_problems "$tmp/pk-both" failed
# a module with no token at all
w noslots 'Available slots:' 'No slots found'
w failed 'error: Failed to load pkcs11 module'
: > "$tmp/slots-empty"
expect_ok no-token cli_no_token_problems "$tmp/noslots" a
w slot-a 'Slot 0 (0x0): x' '  token label        : a'
expect_bad no-token-listed cli_no_token_problems "$tmp/slot-a" a
expect_bad no-token-module-failed cli_no_token_problems "$tmp/failed" a
expect_bad no-token-empty cli_no_token_problems "$tmp/slots-empty" a

# processes, secrets, PAM
w procs '  100 bash' '  101 python3 agent.py'
w procs-ok '  100 bash'
w procs-pk '  100 bash' '  102 pkttyagent --fallback --process=1,2'
expect_ok leftover cli_no_leftover_problems l "$tmp/procs-ok"
expect_bad leftover-pkttyagent cli_no_leftover_problems l "$tmp/procs-pk"
expect_bad leftover-no-file cli_no_leftover_problems l "$tmp/nofile"
expect_ok test-agent cli_no_test_agent_problems "$tmp/procs-ok"
expect_bad test-agent-runs cli_no_test_agent_problems "$tmp/procs"
w j 'Nov 02 service started'
expect_ok secrets cli_no_secret_problems "$tmp/j" pw1 pw2
w j2 'Nov 02 got pw2 here'
expect_bad secrets-leaked cli_no_secret_problems "$tmp/j2" pw1 pw2
: > "$tmp/jempty"
expect_bad secrets-empty-journal cli_no_secret_problems "$tmp/jempty" pw1
w pam-ok 'auth required pam_unix.so' 'account required pam_unix.so'
w pam-permit 'auth required pam_permit.so' 'account required pam_permit.so'
w pam-deny 'auth required pam_deny.so'
w pam-both 'auth sufficient pam_permit.so' 'auth required pam_unix.so'
expect_ok pam cli_pam_problems "$tmp/pam-ok"
expect_bad pam-permit cli_pam_problems "$tmp/pam-permit"
expect_bad pam-no-unix cli_pam_problems "$tmp/pam-deny"
expect_bad pam-both cli_pam_problems "$tmp/pam-both"
expect_bad pam-missing cli_pam_problems "$tmp/nofile"
expect_ok exit0 cli_exit_problems l 0
expect_bad exit1 cli_exit_problems l 1

# the state directory snapshots (snapshot_state lines, the path last)
w s0 'd 1 1 755 - ./1000' 'f 1 1 600 aa ./1000/a' 'f 1 1 600 bb ./1000/a-cert' 'f 1 1 600 cc ./1000/b' 'f 1 1 600 dd ./1000/b-cert'
w s1 'd 1 1 755 - ./1000' 'f 1 1 600 cc ./1000/b' 'f 1 1 600 dd ./1000/b-cert'
w s-extra 'd 1 1 755 - ./1000' 'f 1 1 600 ee ./1000/b' 'f 1 1 600 dd ./1000/b-cert'
w s-both-gone 'd 1 1 755 - ./1000'
expect_ok state-present cli_state_key_problems "$tmp/s0" a present
expect_ok state-absent cli_state_key_problems "$tmp/s1" a absent
expect_bad state-still-there cli_state_key_problems "$tmp/s0" a absent
expect_bad state-not-there cli_state_key_problems "$tmp/s1" a present
expect_ok state-only cli_state_only_problems "$tmp/s0" "$tmp/s1" a
expect_bad state-only-other-changed cli_state_only_problems "$tmp/s0" "$tmp/s-extra" a
expect_bad state-only-other-gone cli_state_only_problems "$tmp/s0" "$tmp/s-both-gone" a
expect_bad state-only-nothing-deleted cli_state_only_problems "$tmp/s0" "$tmp/s0" a
exit "$fail"
