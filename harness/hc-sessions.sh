#!/usr/bin/env bash
# hc-sessions.sh <pid>: under herdr-core, a child terminal for each claude session the loop starts
# while <pid> (run.sh) lives, named after its log (f45-s1-build) and following it with
# hc-session-view.sh. Runs on the host: the container writes the logs to the bind-mounted repo.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
dir=$here/../.harness/logs pid=$1
mkdir -p "$dir"
since=$(mktemp)
trap 'rm -f "$since"' EXIT
declare -A seen=()

while kill -0 "$pid" 2>/dev/null; do
  while IFS= read -r f; do
    [[ -n ${seen[$f]:-} ]] && continue
    seen[$f]=1
    base=${f##*/} base=${base%.log.jsonl}
    # hc names: 1-32 of a-z 0-9 - _ ., not shaped like an id (t7), unique among live terminals.
    name=$(printf %s "${base#*-*-}" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9._' '-' | sed 's/^[-._]*//; s/-*$//' | cut -c1-25)
    [[ -n $name && ! $name =~ ^t[0-9] ]] || name="s-$name"
    for n in "$name" "$name-${base:9:6}"; do
      hc run --bg --no-notify --rm --name "${n%-}" --label "custodio.session=$base" \
        "$here/hc-session-view.sh" "${n%-}" "$f" "$pid" >/dev/null 2>&1 && break
    done
  done < <(find "$dir" -maxdepth 1 -name '*.log.jsonl' -newer "$since")
  sleep 1
done
