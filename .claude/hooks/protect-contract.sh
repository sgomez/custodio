#!/usr/bin/env bash
# PreToolUse on file edits: the builder may not change the contract. Only harness/loop.sh does.
path=$(jq -r '.tool_input.file_path // .tool_input.notebook_path // empty')
case "$(basename -- "$path")" in
  features.json)
    echo "features.json is the contract; only harness/loop.sh marks features as passing. If a verify command cannot work, write BLOCKED.md." >&2
    exit 2
    ;;
esac
exit 0
