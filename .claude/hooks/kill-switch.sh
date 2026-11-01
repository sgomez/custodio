#!/usr/bin/env bash
# PreToolUse: block every tool call of a headless harness agent while AGENT_STOP exists at the project root.
# Interactive sessions (no HARNESS_ROLE, or the fixer) are a person at the keyboard: not blocked.
case ${HARNESS_ROLE:-} in '' | fixer) exit 0 ;; esac
if [ -e "${CLAUDE_PROJECT_DIR:-.}/AGENT_STOP" ]; then
  echo "AGENT_STOP exists: the operator stopped the loop. End the session now." >&2
  exit 2
fi
exit 0
