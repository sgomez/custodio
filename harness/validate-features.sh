#!/usr/bin/env bash
# Check that features.json has the shape the loop expects.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

jq -e '
  (.features | type == "array" and length > 0)
  and ([.features[].id] | length == (unique | length))
  and (.features | all(
        (.id | type == "string")
        and (.title | type == "string")
        and (.description | type == "string")
        and (.depends_on | type == "array")
        and (.passes | type == "boolean")
        and ((.manual // false) or (.verify | type == "string" and length > 0))))
  and ([.features[].id] as $ids | [.features[] | .id as $me | .depends_on[] | select(. != $me)]
       | all(. as $d | $ids | index($d) != null))
  and (.features | all(.id as $me | .depends_on | index($me) == null))
' features.json >/dev/null || {
  echo "features.json is invalid: every feature needs a unique id, title, description, depends_on (existing ids, not itself), passes, and verify unless manual." >&2
  exit 1
}
echo "features.json: $(jq '.features | length' features.json) features, valid."
