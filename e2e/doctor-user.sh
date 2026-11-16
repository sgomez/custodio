#!/usr/bin/env bash
# Runs as the regular account of the doctor-* cases (F204) in a login session (`su -l`): `doctor-user.sh NAME` runs the installed `custodio doctor` once with no terminal, no agent
# and a time limit, and leaves NAME.out, NAME.err and NAME.rc in $OBS (a directory the account can write).
set -u
: "${OBS:?}"
name=${1:?}
rc=0
timeout 30 custodio doctor < /dev/null > "$OBS/$name.out" 2> "$OBS/$name.err" || rc=$?
echo "$rc" > "$OBS/$name.rc"
