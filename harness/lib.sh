#!/usr/bin/env bash
# Shared helpers for the harness scripts. Source it; do not run it.

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; hc_last=$*; hc_status working "$*"; }
die() { log "$1" >&2; exit "${2:-1}"; }

# Status for the Herdr app: an OSC 7501 report on the terminal. run.sh enables it under herdr-core.
hc_status() {
  [ "${HARNESS_HC_STATUS:-0}" = 1 ] || return 0
  local rec="state=$1:app=custodio"
  [ -n "${2:-}" ] && rec="$rec:msg=$(printf %s "$2" | base64 -w0)"
  { printf '\033]7501;%s\033\134' "$rec" > /dev/tty; } 2>/dev/null || true
}
# Exit codes: 2 and 3 stop for a human.
hc_exit() {
  case $? in
    0) hc_status 'done' "${hc_last:-}" ;;
    2 | 3) hc_status blocked "${hc_last:-}" ;;
    130) hc_status idle "stopped" ;;
    *) hc_status error "${hc_last:-}" ;;
  esac
}
if [ "${HARNESS_HC_STATUS:-0}" = 1 ]; then trap hc_exit EXIT; fi

# A session's events, from its transcript or `--output-format stream-json`, as text and tool calls.
# shellcheck disable=SC2034 # read by the scripts that source this file
transcript_format='
  fromjson? |
  if .type == "assistant" then
    .message.content[]? |
    if .type == "text" then .text
    elif .type == "tool_use" then
      "→ \(.name) " + ((.input.command // .input.file_path // .input.pattern // .input.description
        // .input | tostring) | gsub("\\s+"; " ") | .[0:160])
    else empty end
  elif .type == "user" then
    .message.content[]? | select(.type? == "tool_result" and .is_error == true)
    | "  ✗ " + ((.content | tostring) | gsub("\\s+"; " ") | .[0:160])
  else empty end'

# claude_session <role> <log> <claude args...>: a headless session. <log>.jsonl gets its events, which
# the herdr terminals follow (hc-sessions.sh); <log> its final message, as plain `claude -p` prints it.
# Returns 124 when it ran past SESSION_TIMEOUT. claude -p waits for its own background tasks, so once the
# session has reported its result, whatever is left of its process group is killed.
claude_session() {
  local role=$1 logfile=$2 rc=0 pid killed=
  shift 2
  HARNESS_ROLE=$role setsid timeout -k 30 "${SESSION_TIMEOUT:-45m}" claude -p --dangerously-skip-permissions \
    --output-format stream-json --verbose "$@" >"$logfile.jsonl" 2>&1 &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    if grep -q '"type":"result"' "$logfile.jsonl"; then
      for _ in 1 2 3 4 5 6; do kill -0 "$pid" 2>/dev/null || break; sleep 5; done
      kill -0 "$pid" 2>/dev/null && killed=1 && kill -TERM -- "-$pid" 2>/dev/null
      break
    fi
    sleep 5
  done
  wait "$pid" || rc=$?
  [ -z "$killed" ] || rc=0
  { jq -rR 'fromjson? | select(.type == "result") | .result // empty' "$logfile.jsonl"
    grep -v '^{' "$logfile.jsonl"; } > "$logfile" || true
  # A session cut before its result: its last steps instead, so the log is not empty.
  if [ ! -s "$logfile" ]; then
    { echo "(no result: the session was cut; its last steps follow, the full events are in $logfile.jsonl)"
      jq -rR "$transcript_format" "$logfile.jsonl" | tail -n 80; } > "$logfile" || true
  fi
  return "$rc"
}

sha() {
  if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi | cut -d' ' -f1
}

# What a person approves. The features hash ignores `passes`, which the loop changes.
hash_spec() { sha < SPEC.md; }
hash_features() { jq -S 'del(.features[].passes)' features.json | sha; }
# A contract's approved text: ticking or unticking its steps does not change it.
contract_hash() { sed -E 's/^([[:space:]]*- )\[[xX-]\]/\1[ ]/' "$1" | sha; }

approved() {
  [ "${AUTO_APPROVE:-0}" = 1 ] && return 0
  [ -f APPROVALS ] && grep -qx "$1 $("hash_$1")" APPROVALS
}

# commitlint, pinned in package-lock.json.
ensure_node_tools() {
  [ -x node_modules/.bin/commitlint ] || npm ci --silent --no-audit --no-fund || die "npm ci failed."
}

tracked_changes() { [ -n "$(git status --porcelain --untracked-files=no)" ]; }

commit() { git add -- "${@:2}" && git commit -q -m "$1"; }
