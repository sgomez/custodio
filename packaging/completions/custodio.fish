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
complete -c custodio -n __custodio_no_command -a register -d 'Register the module with the browsers'
complete -c custodio -n __custodio_no_command -a fingerprint -d 'Turn the fingerprint on or off'
complete -c custodio -n __custodio_no_command -a doctor -d 'Check the setup'

complete -c custodio -n '__fish_seen_subcommand_from import' -l id -x -d 'Name of the new key'
complete -c custodio -n '__fish_seen_subcommand_from import' -F

complete -c custodio -n '__fish_seen_subcommand_from register' -l module -r -F -d 'Path of the module'
complete -c custodio -n '__fish_seen_subcommand_from register' -l remove -d 'Remove the registration'
complete -c custodio -n '__fish_seen_subcommand_from register' -l refresh-only -d 'Only refresh'

complete -c custodio -n '__fish_seen_subcommand_from list' -s v -l verbose -d 'Show every key in full'

complete -c custodio -n '__custodio_first_arg_of list delete' -a '(__custodio_key_ids)'
complete -c custodio -n '__custodio_first_arg_of fingerprint' -a 'enable disable'
