#!/usr/bin/env bash
# hc-sessions.sh <pid>: under herdr-core, while <pid> (run.sh) lives, a child terminal per feature
# (f45) that follows all its claude sessions, and under it one per session (f45-s1-build); sessions
# of no feature (planner) hang from run.sh's terminal. Runs on the host: the container writes the
# session logs to the bind-mounted repo. See hc-view.sh.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
dir=$(cd "$here/.." && pwd)/.harness/logs pid=$1
mkdir -p "$dir"
since=$(mktemp)
trap 'rm -f "$since"' EXIT
declare -A seen=()
feature='' feature_term=''

# open <name> <hc run options...> -- <hc-view.sh args...>: prints the new terminal's address.
open() {
  local name n
  # hc names: 1-32 of a-z 0-9 - _ ., not shaped like an id (t7), unique among live terminals.
  name=$(printf %s "$1" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9._' '-' | sed 's/^[-._]*//; s/-*$//' | cut -c1-25)
  [[ -n $name && ! $name =~ ^t[0-9] ]] || name="s-$name"
  shift
  local opts=()
  while [[ $1 != -- ]]; do opts+=("$1"); shift; done
  shift
  for n in "$name" "$name-$(date +%H%M%S)"; do
    hc run --bg --json --no-notify --rm --name "$n" ${opts[@]+"${opts[@]}"} "$here/hc-view.sh" "$1" "$n" "${@:2}" \
      2>/dev/null | jq -r '.address // empty' | grep . && return
  done
}

while kill -0 "$pid" 2>/dev/null; do
  while IFS= read -r f; do
    [[ -n ${seen[$f]:-} ]] && continue
    seen[$f]=1
    base=${f##*/} base=${base%.log.jsonl} rest=${base#*-*-} parent=()
    if [[ $rest =~ ^(F[0-9]+)- ]]; then
      if [[ ${BASH_REMATCH[1]} != "$feature" ]]; then
        [[ -n $feature_term ]] && hc send "$feature_term" stop >/dev/null 2>&1
        feature=${BASH_REMATCH[1]}
        feature_term=$(open "$feature" -- feature "$f" "$pid")
      fi
      [[ -n $feature_term ]] && parent=(--parent "$feature_term")
    fi
    open "$rest" ${parent[@]+"${parent[@]}"} -- session "$f" "$pid" >/dev/null
  done < <(find "$dir" -maxdepth 1 -name '*.log.jsonl' -newer "$since" | sort)
  sleep 1
done
