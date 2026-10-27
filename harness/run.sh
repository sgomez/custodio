#!/usr/bin/env bash
# Run the build loop in the dev container. From the repository root on your Mac:
#   export CLAUDE_CODE_OAUTH_TOKEN=...   # once, from `claude setup-token`
#   harness/run.sh                       # loop
#   harness/run.sh bash                  # a shell in the container
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
engine=$(command -v podman || command -v docker)
: "${CLAUDE_CODE_OAUTH_TOKEN:?Set CLAUDE_CODE_OAUTH_TOKEN (run: claude setup-token)}"

"$engine" build -q -t custodio-dev -f harness/Containerfile harness >/dev/null
"$engine" volume create custodio-target >/dev/null 2>&1 || true

exec "$engine" run --rm -it \
  -v "$PWD":/work \
  -v custodio-target:/work/target \
  -e CLAUDE_CODE_OAUTH_TOKEN \
  -e MAX_SESSIONS -e MAX_ATTEMPTS \
  -e GIT_AUTHOR_NAME="$(git config user.name)" -e GIT_AUTHOR_EMAIL="$(git config user.email)" \
  -e GIT_COMMITTER_NAME="$(git config user.name)" -e GIT_COMMITTER_EMAIL="$(git config user.email)" \
  custodio-dev "${@:-harness/loop.sh}"
