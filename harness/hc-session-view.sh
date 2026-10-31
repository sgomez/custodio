#!/usr/bin/env bash
# hc-session-view.sh <name> <session .jsonl> <pid>: runs in the terminal hc-sessions.sh opens. Prints the
# session as it runs, reports each tool call as `working`, and its result as `done` or `error`;
# a finished terminal loses its state, so the final one lingers HC_SESSION_LINGER seconds. When <pid>
# (run.sh) ends first, the container stopped the session.
set -uo pipefail
name=$1 file=$2 pid=$3
cd "$(dirname "$0")/.." || exit
# shellcheck source=harness/lib.sh
. harness/lib.sh
export HARNESS_HC_STATUS=1
stty -echo 2>/dev/null
printf '\033]2;%s\007── %s ──\n' "$name" "$name"
hc_status working "$name"

tail -n +1 -F "$file" 2>/dev/null | jq --unbuffered -rR "$transcript_format" |
  while IFS= read -r line; do
    printf '%s\n' "$line"
    if [[ $line == "→ "* ]]; then hc_status working "${line:2:80}"; fi
  done &

until result=$(grep -F '"type":"result"' "$file" 2>/dev/null | tail -n1); [[ -n $result ]]; do
  kill -0 "$pid" 2>/dev/null || break
  sleep 1
done
sleep 0.5
pkill -P $$ 2>/dev/null

IFS=$'\t' read -r state msg < <(jq -r '
  [if .subtype == "success" and .is_error == false then "done" else "error" end,
   ((.result // .subtype // "stopped without a result") | tostring | split("\n") | map(select(test("\\S")))[0] // "" | .[0:80])]
  | @tsv' <<<"${result:-null}")
hc_status "$state" "$msg"
[[ $state == "done" ]] && echo "✓ $msg" || echo "✗ $msg"
sleep "${HC_SESSION_LINGER:-60}"
