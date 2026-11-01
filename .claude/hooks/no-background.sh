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
    if jq -r '.tool_input.command' <<< "$input" | grep -qE '(^|[;&|(]|\b(do|then))[[:space:]]*sleep\b|\b(until|while)\b.*\b(pgrep|sleep)\b'; then
      deny "Polling with sleep, until or while is not allowed in the build loop."
    fi ;;
esac
exit 0
