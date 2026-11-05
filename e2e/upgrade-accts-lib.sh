# shellcheck shell=bash
# Sourced by upgrade.sh and upgrade-accts-selftest.sh (F96, acceptance 10 of SPEC.md): the judgements of the two-account part of the upgrade
# case, as functions of the evidence files that upgrade-accts.sh and upgrade-accts-user.sh leave in the directory ACC. Each prints one
# problem per line and nothing when the evidence is right, so the self-test can show that every judgement fails on bad input.
#
# ACC layout: PHASE/USER.list (custodio list), PHASE/USER-ID.der (certificate through the PKCS#11 module) for PHASE before|after;
# bob-old.der, bob-new.der (the certificate of bob's rsa1 before and after ReplaceCertificate); sign/USER-ID.sig, sign/USER-ID.requests
# (the agent's log grew by that many lines), sign/USER-denied ("EXIT-STATUS REQUESTS SIGNATURE-BYTES").
# The accounts and what each holds. The id rsa1 is held by both (two different keys): ids alone cannot tell owners.
ACCT_ALICE_IDS="ec1 rsa1"
ACCT_BOB_IDS="bobonly rsa1"

acct_ids_of() { sed -n 's/^id: //p' "$1" | sort | tr '\n' ' ' | sed 's/ $//'; }
acct_sha() { sha256sum < "$1" | cut -d' ' -f1; }
acct_expect() { # USER: the ids of the account
    case $1 in alice) echo "$ACCT_ALICE_IDS" ;; bob) echo "$ACCT_BOB_IDS" ;; *) return 1 ;; esac
}
acct_other() { case $1 in alice) echo bob ;; bob) echo alice ;; esac; }

# acct_list_problems FILE USER: FILE (custodio list as USER) shows exactly the ids of USER: not one missing, not one of the other account
acct_list_problems() {
    local file=$1 user=$2 got want id
    [ -s "$file" ] || { echo "$user: $file is missing or empty"; return; }
    got=$(acct_ids_of "$file")
    want=$(acct_expect "$user")
    [ "$got" = "$want" ] && return
    for id in $want; do [[ " $got " == *" $id "* ]] || echo "$user: the list does not show $id"; done
    for id in $got; do [[ " $want " == *" $id "* ]] || echo "$user: the list shows $id, which is not one of his or her keys"; done
    [ "$(printf '%s\n' "$got" | tr ' ' '\n' | sort | uniq -d | wc -l)" -eq 0 ] || echo "$user: an id is listed twice"
}

# acct_cert_files_problems DIR: the certificate of every id of both accounts is there, and the two accounts' certificates for the shared id differ
acct_cert_files_problems() {
    local dir=$1 u id
    for u in alice bob; do
        for id in $(acct_expect "$u"); do [ -s "$dir/$u-$id.der" ] || echo "$u: no certificate for $id in $dir"; done
    done
    if [ -s "$dir/alice-rsa1.der" ] && [ -s "$dir/bob-rsa1.der" ] && [ "$(acct_sha "$dir/alice-rsa1.der")" = "$(acct_sha "$dir/bob-rsa1.der")" ]; then
        echo "rsa1 shows the same certificate to alice and to bob (one key for two owners)"
    fi
}

# acct_seed_problems ACC: before the upgrade: both lists exact, certificates read, and bob's rsa1 certificate is the replacement, not the original
acct_seed_problems() {
    local acc=$1 u
    for u in alice bob; do acct_list_problems "$acc/before/$u.list" "$u"; done
    acct_cert_files_problems "$acc/before"
    if [ ! -s "$acc/bob-old.der" ] || [ ! -s "$acc/bob-new.der" ]; then echo "the original and the replacing certificate were not kept"; return; fi
    [ "$(acct_sha "$acc/bob-old.der")" != "$(acct_sha "$acc/bob-new.der")" ] || echo "the replacing certificate is the original one"
    if [ -s "$acc/before/bob-rsa1.der" ]; then
        [ "$(acct_sha "$acc/before/bob-rsa1.der")" != "$(acct_sha "$acc/bob-old.der")" ] || echo "before the upgrade bob's rsa1 still shows the original certificate"
        [ "$(acct_sha "$acc/before/bob-rsa1.der")" = "$(acct_sha "$acc/bob-new.der")" ] || echo "before the upgrade bob's rsa1 does not show the replacing certificate"
    fi
}

# acct_after_problems ACC: after the upgrade each list is exactly the account's own and equal to the one before, every certificate is the one before,
# and the replaced one is the new certificate
acct_after_problems() {
    local acc=$1 u id
    for u in alice bob; do
        acct_list_problems "$acc/after/$u.list" "$u"
        if [ -s "$acc/before/$u.list" ] && [ -s "$acc/after/$u.list" ] && [ "$(acct_sha "$acc/before/$u.list")" != "$(acct_sha "$acc/after/$u.list")" ]; then
            echo "$u: the list after the upgrade differs from the one before"
        fi
    done
    acct_cert_files_problems "$acc/after"
    for u in alice bob; do
        for id in $(acct_expect "$u"); do
            [ -s "$acc/before/$u-$id.der" ] && [ -s "$acc/after/$u-$id.der" ] || continue
            [ "$(acct_sha "$acc/before/$u-$id.der")" = "$(acct_sha "$acc/after/$u-$id.der")" ] || echo "$u: the certificate of $id changed in the upgrade"
        done
    done
    if [ -s "$acc/after/bob-rsa1.der" ] && [ -s "$acc/bob-old.der" ] && [ -s "$acc/bob-new.der" ]; then
        [ "$(acct_sha "$acc/after/bob-rsa1.der")" != "$(acct_sha "$acc/bob-old.der")" ] || echo "after the upgrade bob's rsa1 shows the original certificate, not the replaced one"
        [ "$(acct_sha "$acc/after/bob-rsa1.der")" = "$(acct_sha "$acc/bob-new.der")" ] || echo "after the upgrade bob's rsa1 is not the replacing certificate"
    fi
}

# acct_state_problems STATE_FILE ALICE_UID BOB_UID CUSTODIO_UID: the snapshot (snapshot_state) holds ./<uid>/<id> (one record: key and certificate) for each key of
# each account and no other file: directory 0700 and files 0600, every one owned by custodio (the owner is the directory), the two rsa1 files with different content
acct_state_problems() {
    local file=$1 au=$2 bu=$3 cu=$4 u uid id name kind owner _gid mode hash path want got
    local -A seen
    while read -r kind owner _gid mode hash path; do
        case $kind in
        f) seen[$path]="$owner $mode $hash" ;;
        d) case $path in "./$au" | "./$bu") [ "$mode" = 700 ] || echo "state: $path has mode $mode, expected 700"; [ "$owner" = "$cu" ] || echo "state: $path is owned by $owner, not custodio" ;; esac ;;
        esac
    done < "$file"
    for u in alice bob; do
        if [ "$u" = alice ]; then uid=$au; else uid=$bu; fi
        want=''
        for id in $(acct_expect "$u"); do
            name=$id # the store keeps one record file per key, certificate included
            want="$want ./$uid/$name"
            if [ -z "${seen[./$uid/$name]+x}" ]; then echo "state: no file ./$uid/$name ($u's $id)"; continue; fi
            read -r owner mode hash <<< "${seen[./$uid/$name]}"
            [ "$owner" = "$cu" ] || echo "state: ./$uid/$name is owned by $owner, not custodio"
            [ "$mode" = 600 ] || echo "state: ./$uid/$name has mode $mode, expected 600"
        done
        got=$(for path in "${!seen[@]}"; do case $path in "./$uid"/*) echo "$path" ;; esac; done | LC_ALL=C sort | tr '\n' ' ')
        for path in $got; do [[ " $want " == *" $path "* ]] || echo "state: $path is not one of $u's keys"; done
    done
    if [ -n "${seen[./$au/rsa1]+x}" ] && [ -n "${seen[./$bu/rsa1]+x}" ]; then
        [ "${seen[./$au/rsa1]##* }" != "${seen[./$bu/rsa1]##* }" ] || echo "state: ./$au/rsa1 and ./$bu/rsa1 hold the same file"
    fi
}

# acct_sign_problems ACC USER: one signature per key of USER made one request in USER's agent, verifies against USER's certificate after the upgrade and
# against none of the other account's; a denied signature failed, was asked and wrote nothing
acct_sign_problems() {
    local acc=$1 u=$2 o id pub f req st n bytes
    o=$(acct_other "$u")
    for id in $(acct_expect "$u"); do
        f=$acc/sign/$u-$id
        if [ ! -s "$f.sig" ]; then echo "$u: no signature with $id"; continue; fi
        req=$(cat "$f.requests" 2> /dev/null || true)
        [ "$req" = 1 ] || echo "$u: the signature with $id made '${req:-no}' requests in the agent, expected 1"
        if [ ! -s "$acc/after/$u-$id.der" ]; then echo "$u: no certificate of $id to verify against"; continue; fi
        acct_verifies "$f.sig" "$acc/sign/data.bin" "$acc/after/$u-$id.der" "$id" || echo "$u: the signature with $id does not verify against his or her certificate"
        for n in $(acct_expect "$o"); do
            [ -s "$acc/after/$o-$n.der" ] || continue
            ! acct_verifies "$f.sig" "$acc/sign/data.bin" "$acc/after/$o-$n.der" "$id" || echo "$u: the signature with $id verifies against $o's $n"
        done
    done
    f=$acc/sign/$u-denied
    if [ ! -s "$f" ]; then echo "$u: no record of the denied signature"; return; fi
    read -r st req bytes < "$f"
    { [ -n "${st:-}" ] && [ "$st" != 0 ]; } || echo "$u: the denied signature did not fail (status '${st:-}')"
    [ "${req:-}" = 1 ] || echo "$u: the denied signature made '${req:-}' requests, expected 1"
    [ "${bytes:-}" = 0 ] || echo "$u: the denied signature wrote '${bytes:-}' bytes"
}

# acct_verifies SIG DATA CERT: the signature is SHA-256 of DATA by the key of CERT (RSA, or ECDSA in the DER form of openssl)
acct_verifies() { # SIG DATA CERT (a fourth argument is ignored)
    local pub rc=1
    pub=$(mktemp)
    if openssl x509 -inform DER -in "$3" -pubkey -noout > "$pub" 2> /dev/null; then
        openssl dgst -sha256 -verify "$pub" -signature "$1" "$2" > /dev/null 2>&1 && rc=0
    fi
    rm -f "$pub"
    return "$rc"
}
