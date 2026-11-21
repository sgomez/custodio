# bash completion for custodio. Loaded on first use by bash-completion from
# /usr/share/bash-completion/completions/custodio.
#
# The key ids come from `custodio __key-ids`: it asks the service for the list only (no polkit
# request, nothing written), prints nothing and exits 1 when the service is absent or does not
# answer within 2 s. Every line it prints is read as data, never as shell text.

_custodio_key_ids() {
    local id
    COMPREPLY=()
    while IFS= read -r id; do
        [[ $id == "$1"* ]] && COMPREPLY+=("$id")
    done < <(custodio __key-ids 2>/dev/null)
}

_custodio_files() {
    local file
    COMPREPLY=()
    while IFS= read -r file; do
        COMPREPLY+=("$file")
    done < <(compgen -f -- "$1")
    compopt -o filenames 2>/dev/null
}

_custodio_words() {
    local word
    COMPREPLY=()
    while IFS= read -r word; do
        COMPREPLY+=("$word")
    done < <(compgen -W "$1" -- "$2")
}

# The options of the action being typed after `setup <topic> <action>`: only `--module` takes a value.
_custodio_setup_options() {
    case "${COMP_WORDS[2]-} ${COMP_WORDS[3]-}" in
        "browsers enable" | "browsers refresh") _custodio_words "--module -h --help" "$1" ;;
        *) _custodio_words "-h --help" "$1" ;;
    esac
}

# The topics after `setup`, the actions after a topic, a file after `--module`.
_custodio_setup_words() {
    case $COMP_CWORD in
        2) _custodio_words "browsers fingerprint" "$1" ;;
        3)
            case ${COMP_WORDS[2]} in
                browsers) _custodio_words "enable disable refresh" "$1" ;;
                fingerprint) _custodio_words "enable disable" "$1" ;;
            esac
            ;;
        *)
            case "${COMP_WORDS[2]-} ${COMP_WORDS[3]-}" in
                "browsers enable" | "browsers refresh")
                    [[ ${COMP_WORDS[COMP_CWORD - 1]} == --module ]] && _custodio_files "$1"
                    ;;
            esac
            ;;
    esac
}

_custodio() {
    local cur=${COMP_WORDS[COMP_CWORD]} cmd=${COMP_WORDS[1]-} prev=${COMP_WORDS[COMP_CWORD - 1]}
    COMPREPLY=()

    if ((COMP_CWORD == 1)); then
        if [[ $cur == -* ]]; then
            _custodio_words "-h --help" "$cur"
        else
            _custodio_words "import list delete setup doctor" "$cur"
        fi
        return
    fi

    if [[ $cur == -* && $prev != -- ]]; then
        case $cmd in
            import) _custodio_words "--id -h --help" "$cur" ;;
            setup) _custodio_setup_options "$cur" ;;
            list) _custodio_words "-v --verbose -h --help" "$cur" ;;
            delete | doctor) _custodio_words "-h --help" "$cur" ;;
        esac
        return
    fi

    case $cmd in
        import)
            # `--id` names a new key: nothing to complete.
            [[ $prev == --id ]] || _custodio_files "$cur"
            ;;
        list | delete)
            # One key id, after the options (`-v` for list) and an optional `--`.
            local i word
            for ((i = 2; i < COMP_CWORD; i++)); do
                word=${COMP_WORDS[i]}
                [[ $word == -- || ($cmd == list && ($word == -v || $word == --verbose)) ]] || return
            done
            _custodio_key_ids "$cur"
            ;;
        setup) _custodio_setup_words "$cur" ;;
    esac
}

complete -F _custodio custodio
