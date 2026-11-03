#!/usr/bin/env bash
# Run the build loop in the dev container. From the repository root on your Mac:
#   export CLAUDE_CODE_OAUTH_TOKEN=...   # once, from `claude setup-token`
#   harness/run.sh                       # pipeline: plan, split, build
#   harness/run.sh bash                  # a shell in the container
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
engine=$(command -v podman || command -v docker)
: "${CLAUDE_CODE_OAUTH_TOKEN:?Set CLAUDE_CODE_OAUTH_TOKEN (run: claude setup-token)}"

stable=$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)
nightly=$(sed -n 's/^nightly_toolchain := "\(.*\)"$/\1/p' justfile)
"$engine" build -q -t custodio-dev --build-arg STABLE="$stable" --build-arg NIGHTLY="$nightly" \
  -f harness/Containerfile harness >/dev/null
"$engine" volume create custodio-target >/dev/null 2>&1 || true

# Rootless podman maps the host user to root in the container; keep-id maps it to `dev` instead.
# The e2e targets run systemd containers in a nested rootless podman (F45), which needs no more than: SYS_ADMIN for
# newuidmap, /proc unmasked to mount a fresh one, and systemd mode for a writable cgroup (docs/findings.md, F45).
userns=() target_opts=
if [[ $engine == *podman ]]; then userns=(--userns=keep-id --cap-add=SYS_ADMIN '--security-opt=unmask=/proc/*' --systemd=always) target_opts=:U; fi
hc_status=0
if [[ -n ${HC_TERMINAL_ID:-} ]]; then
  hc_status=1
  if command -v hc >/dev/null && command -v jq >/dev/null; then harness/hc-sessions.sh $$ & fi
fi

"$engine" run --rm -it ${userns[@]+"${userns[@]}"} \
  -v "$PWD":/work \
  -v "custodio-target:/work/target$target_opts" \
  -e CLAUDE_CODE_OAUTH_TOKEN -e HARNESS_HC_STATUS="$hc_status" \
  -e BASH_MAX_TIMEOUT_MS=1800000 \
  -e AUTO_APPROVE -e MAX_SESSIONS -e MAX_ATTEMPTS -e MAX_CONTRACT_ROUNDS -e MAX_FEATURE_SESSIONS -e MAX_AMENDMENTS -e SESSION_TIMEOUT \
  -e GIT_AUTHOR_NAME="$(git config user.name)" -e GIT_AUTHOR_EMAIL="$(git config user.email)" \
  -e GIT_COMMITTER_NAME="$(git config user.name)" -e GIT_COMMITTER_EMAIL="$(git config user.email)" \
  custodio-dev "${@:-harness/pipeline.sh}"
