# F192 needs a rebuild of the dev container

`harness/Containerfile` now installs `bash-completion`, `zsh` and `fish`, and CI jobs that run the CLI's tests do too. The running dev
container lacks them, so the `verify` cannot pass here.

Please rebuild the dev container from `harness/Containerfile`. Then remove this file; the next session runs the `verify`
(`test -r /usr/share/bash-completion/bash_completion`, zsh `compinit`, `fish --no-config`).
