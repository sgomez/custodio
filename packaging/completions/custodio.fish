# fish completion for custodio. Loaded on first use by fish from
# /usr/share/fish/vendor_completions.d/custodio.fish.
#
# The key ids come from `custodio __key-ids`: it asks the service for the list only (no polkit
# request, nothing written), prints nothing and exits 1 when the service is absent or does not
# answer within 2 s. Every line it prints is a candidate as it is, never shell text.

# The words typed so far, without the one being completed and without options.
function __custodio_args
    set -l words (commandline -opc)
    set -e words[1]
    for word in $words
        string match -q -- '-*' $word; or echo $word
    end
end

function __custodio_key_ids
    custodio __key-ids 2>/dev/null
end

# True when the command is `name` and no argument follows it yet.
function __custodio_first_arg_of
    set -l args (__custodio_args)
    test (count $args) -eq 1; and contains -- $args[1] $argv
end

function __custodio_no_command
    test (count (__custodio_args)) -eq 0
end

complete -c custodio -f
complete -c custodio -s h -l help -d 'Show the help'

complete -c custodio -n __custodio_no_command -a import -d 'Import a key from a PKCS#12 file'
complete -c custodio -n __custodio_no_command -a list -d 'List the keys'
complete -c custodio -n __custodio_no_command -a delete -d 'Delete a key'
complete -c custodio -n __custodio_no_command -a setup -d 'Set up the browsers and the fingerprint'
complete -c custodio -n __custodio_no_command -a doctor -d 'Check the setup'

complete -c custodio -n '__fish_seen_subcommand_from import' -l id -x -d 'Name of the new key'
complete -c custodio -n '__fish_seen_subcommand_from import' -F

# `setup <topic> <action>`: the topics, then the actions of the topic, then `--module` where it applies.
function __custodio_setup_is
    test (string join ' ' (__custodio_args)) = "$argv"
end

function __custodio_setup_at_topic
    __custodio_setup_is setup
end

complete -c custodio -n __custodio_setup_at_topic -a browsers -d 'Add or remove the module in the browsers'
complete -c custodio -n __custodio_setup_at_topic -a fingerprint -d 'Let a finger answer polkit dialogs'
complete -c custodio -n '__custodio_setup_is setup browsers' -a enable -d 'Add the module to the browser profiles'
complete -c custodio -n '__custodio_setup_is setup browsers' -a disable -d 'Remove the module from the browser profiles'
complete -c custodio -n '__custodio_setup_is setup browsers' -a refresh -d 'Update the Firefox snap copy'
complete -c custodio -n '__custodio_setup_is setup fingerprint' -a enable -d 'Let a finger answer polkit dialogs'
complete -c custodio -n '__custodio_setup_is setup fingerprint' -a disable -d 'Stop a finger answering polkit dialogs'
complete -c custodio -n '__custodio_setup_is setup browsers enable' -l module -r -F -d 'Path of the module'
complete -c custodio -n '__custodio_setup_is setup browsers refresh' -l module -r -F -d 'Path of the module'

complete -c custodio -n '__fish_seen_subcommand_from list' -s v -l verbose -d 'Show every key in full'

complete -c custodio -n '__custodio_first_arg_of list delete' -a '(__custodio_key_ids)'
