#!/usr/bin/env bash
# hc-view.sh session <name> <log.jsonl> <pid> | feature <id> <first log.jsonl> <pid>: runs in a
# terminal hc-sessions.sh opens. A session terminal follows one claude session; a feature terminal
# follows each of the feature's sessions in turn, until a line on stdin (the loop moved on) or the
# end of <pid> (run.sh). Both report progress as their herdr state; a finished terminal loses it,
# so the final one lingers HC_SESSION_LINGER seconds.
set -uo pipefail
cd "$(dirname "$0")/.." || exit
# shellcheck source=harness/lib.sh
. harness/lib.sh
export HARNESS_HC_STATUS=1
stty -echo 2>/dev/null
mode=$1 name=$2 file=$3 pid=$4 stopped=0 state=idle msg=

alive() {
  kill -0 "$pid" 2>/dev/null || return 1
  if ((!stopped)) && read -r -t 0.1 _; then stopped=1; fi
  ((!stopped))
}

# follow <log.jsonl> <label>: prints the session until its result; leaves it in $state and $msg.
follow() {
  local result=
  printf '\n── %s ──\n' "$2"
  hc_status working "$2"
  tail -n +1 -F "$1" 2>/dev/null | jq --unbuffered -rR "$transcript_format" |
    while IFS= read -r line; do
      printf '%s\n' "$line"
      if [[ $line == "→ "* ]]; then hc_status working "$2 ${line:2:70}"; fi
    done &
  until result=$(grep -F '"type":"result"' "$1" 2>/dev/null | tail -n1); [[ -n $result ]]; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 1
  done
  sleep 0.5
  pkill -P $$ 2>/dev/null
  IFS=$'\t' read -r state msg < <(jq -r '
    [if .subtype == "success" and .is_error == false then "done" else "error" end,
     ((.result // .subtype // "stopped without a result") | tostring
      | split("\n") | map(select(test("\\S")))[0] // "" | .[0:80])]
    | @tsv' <<<"${result:-null}")
  if [[ $state == "done" ]]; then echo "✓ $msg"; else echo "✗ $msg"; fi
}

label() { local b=${1##*/}; b=${b%.log.jsonl}; printf %s "${b#*-*-}"; }

printf '\033]2;%s\007' "$name"
if [[ $mode == session ]]; then
  follow "$file" "$(label "$file")"
else
  last=
  while alive; do
    next=$(find .harness/logs -maxdepth 1 -name "*-$name-*.log.jsonl" | sort |
      awk -v from="$file" -v last="$last" '$0 >= from && $0 > last' | head -n1)
    if [[ -z $next ]]; then sleep 1; continue; fi
    follow "$next" "$(label "$next")"
    last=$next
    hc_status working "$(label "$next"): $msg"
  done
  if jq -e --arg id "$name" 'any(.features[]; .id == $id and .passes)' features.json >/dev/null 2>&1; then
    state="done" msg=passes
  elif [[ -e BLOCKED.md ]]; then
    state=blocked msg="BLOCKED.md"
  else
    state=idle msg="stopped${msg:+: $msg}"
  fi
  echo "── $name: $msg ──"
fi
hc_status "$state" "$msg"
sleep "${HC_SESSION_LINGER:-60}"
