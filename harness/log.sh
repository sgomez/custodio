#!/usr/bin/env bash
# Follow the Claude session running in the active dev container, switching to each new session.
# Runs on the host: `just log`. Ctrl-C to stop; the loop keeps running.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=harness/lib.sh
. harness/lib.sh

engine=$(command -v podman || command -v docker)
container=$("$engine" ps --filter ancestor=custodio-dev --format '{{.Names}}' | head -n1)
[ -n "$container" ] || die "No dev container is running; start one with just harness run."
log "Following $container"

# Short polls, not one long exec: a long exec outlives Ctrl-C inside the container.
in_container() { "$engine" exec "$container" bash -c "$1" 2>/dev/null; }

format='
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

file='' shown=0
while "$engine" inspect "$container" >/dev/null 2>&1; do
  # shellcheck disable=SC2016 # expanded inside the container
  read -r newest lines < <(in_container 'f=$(ls -t ~/.claude/projects/-work/*.jsonl | head -n1)
    echo "$f $(wc -l < "$f")"') || { sleep 2; continue; }
  if [ "$newest" != "$file" ]; then
    file=$newest shown=$(( lines > 40 ? lines - 40 : 0 ))
    printf '\n── new session %s ──\n' "$(date +%H:%M:%S)"
  fi
  if (( lines > shown )); then
    in_container "sed -n '$((shown + 1)),${lines}p' '$file'" | jq -rR "$format"
    shown=$lines
  fi
  sleep 2
done
log "$container stopped."
