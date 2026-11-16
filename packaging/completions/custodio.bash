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

_custodio() {
    local cur=${COMP_WORDS[COMP_CWORD]} cmd=${COMP_WORDS[1]-} prev=${COMP_WORDS[COMP_CWORD - 1]}
    COMPREPLY=()

    if ((COMP_CWORD == 1)); then
        if [[ $cur == -* ]]; then
            _custodio_words "-h --help" "$cur"
        else
            _custodio_words "import list delete register fingerprint doctor" "$cur"
        fi
        return
    fi

    if [[ $cur == -* && $prev != -- ]]; then
        case $cmd in
            import) _custodio_words "--id -h --help" "$cur" ;;
            register) _custodio_words "--module --remove --refresh-only -h --help" "$cur" ;;
            list | delete | fingerprint | doctor) _custodio_words "-h --help" "$cur" ;;
        esac
        return
    fi

    case $cmd in
        import)
            # `--id` names a new key: nothing to complete.
            [[ $prev == --id ]] || _custodio_files "$cur"
            ;;
        list | delete)
            if ((COMP_CWORD == 2)) || { ((COMP_CWORD == 3)) && [[ $prev == -- ]]; }; then
                _custodio_key_ids "$cur"
            fi
            ;;
        register)
            [[ $prev == --module ]] && _custodio_files "$cur"
            ;;
        fingerprint)
            ((COMP_CWORD == 2)) && _custodio_words "enable disable" "$cur"
            ;;
    esac
}

complete -F _custodio custodio
