#!/usr/bin/env bash
# PreToolUse on file edits. Each harness role may only write its own artifacts:
#   planner → SPEC.md, initializer → features.json, nobody → APPROVALS (only harness/approve.sh).
# HARNESS_ROLE is set by the harness scripts; an interactive session with a person has none.
# These hooks stop mistakes, not a determined agent: Bash can still write any file.
path=$(jq -r '.tool_input.file_path // .tool_input.notebook_path // empty')
role=${HARNESS_ROLE:-}
deny() { echo "$1" >&2; exit 2; }

case "$(basename -- "$path")" in
  APPROVALS)
    deny "APPROVALS records what a person approved; only harness/approve.sh writes it." ;;
  SPEC.md | IDEA.md)
    [ -z "$role" ] || [ "$role" = planner ] \
      || deny "SPEC.md is approved by a person. If it is wrong or incomplete, write BLOCKED.md." ;;
  features.json)
    [ -z "$role" ] || [ "$role" = initializer ] \
      || deny "features.json is approved by a person and only the loop marks features as passing. If a feature or its verify command cannot work, write BLOCKED.md." ;;
esac
exit 0
