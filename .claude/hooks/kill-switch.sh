#!/usr/bin/env bash
# PreToolUse: block every tool call while AGENT_STOP exists at the project root.
if [ -e "${CLAUDE_PROJECT_DIR:-.}/AGENT_STOP" ]; then
  echo "AGENT_STOP exists: the operator stopped the loop. Commit what you have and end the session." >&2
  exit 2
fi
exit 0
