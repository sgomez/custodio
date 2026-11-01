#!/usr/bin/env bash
# PreToolUse: a headless harness agent runs every command in the foreground. A background task or a wait loop
# keeps `claude -p` alive after the session ends (F64: a `pgrep` loop that matched itself) and wastes turns.
case ${HARNESS_ROLE:-} in '' | fixer) exit 0 ;; esac
input=$(cat)
deny() { echo "$1 Run the command in the foreground with \`timeout <seconds>\` instead." >&2; exit 2; }
case $(jq -r '.tool_name' <<< "$input") in
  Monitor | ScheduleWakeup | CronCreate) deny "Background waits are not allowed in the build loop." ;;
  Bash)
    [ "$(jq -r '.tool_input.run_in_background // false' <<< "$input")" != true ] \
      || deny "run_in_background is not allowed in the build loop."
    cmd=$(jq -r '.tool_input.command' <<< "$input")
    # A short sleep (a service starting) is fine; a long one or an unbounded wait loop is not.
    if grep -qE '(^|[;&|(]|\b(do|then))[[:space:]]*sleep[[:space:]]+(inf|[0-9]{2,}|[1-9][0-9]*[mhd])' <<< "$cmd"; then
      deny "A sleep of 10 s or more is not allowed in the build loop."
    fi
    if grep -qE '\b(until|while)\b.*\b(pgrep|sleep)\b' <<< "$cmd" \
      && ! grep -qE '\btimeout[[:space:]]+[^;&|]*\b(until|while)\b' <<< "$cmd"; then
      deny "A wait loop must run inside \`timeout <seconds>\`, e.g. \`timeout 60 sh -c 'until ...; do sleep 1; done'\`."
    fi ;;
esac
exit 0
