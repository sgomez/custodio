# shellcheck shell=bash
# Sourced by the refusal self-test and by refusal.sh. static_problems FILE...: the refusal case must leave the work to the package, so neither
# its section of refusal.sh (between the BEGIN/END markers) nor the files it calls may stop, start or remove anything of Custodio, or change the
# bus. A list of forbidden commands applied to this case only; it is not a check of guest.sh, which other targets use to start the service.
FORBIDDEN=(
    'systemctl[[:space:]]+(-[^[:space:]]+[[:space:]]+)*(start|restart|stop|reload|daemon-reload|enable|disable|mask|kill)'
    '(^|[^[:alnum:]_-])(kill|pkill|killall)([[:space:]]|$)'
    '(^|[^[:alnum:]_-])(rm|unlink|rmdir|mv)[[:space:]]'
    'dpkg[[:space:]]+(-[rPi]|--remove|--purge|--install|--configure)'
    'apt(-get)?[[:space:]]+(-[^[:space:]]+[[:space:]]+)*(remove|purge|autoremove)'
    'dbus-broker'
    '/etc/dbus-1'
    '>>?[[:space:]]*/(etc|usr|var|lib)/'
    '(^|[^[:alnum:]_-])(tee|cp|ln|install|sed[[:space:]]+-i)[[:space:]]+(-[^[:space:]]+[[:space:]]+)*[^|]*(/etc/|/usr/|/lib/|/var/)'
    'update-alternatives|dpkg-divert'
)
SECTION_BEGIN='# BEGIN refusal-case'
SECTION_END='# END refusal-case'

# static_problems FILE...: a file named refusal.sh is read between its markers, any other file whole; comment lines are ignored.
static_problems() {
    local f body pat bad=0 n
    for f in "$@"; do
        if [ ! -f "$f" ]; then echo "static: $f does not exist"; bad=1; continue; fi
        if [ "$(basename "$f")" = refusal.sh ]; then
            if [ "$(grep -cxF "$SECTION_BEGIN" "$f")" -ne 1 ] || [ "$(grep -cxF "$SECTION_END" "$f")" -ne 1 ]; then
                echo "static: $f lacks its section markers"; bad=1; continue
            fi
            body=$(sed -n "/^$SECTION_BEGIN\$/,/^$SECTION_END\$/p" "$f")
        else
            body=$(cat "$f")
        fi
        body=$(grep -v '^[[:space:]]*#' <<< "$body" || true)
        n=$(grep -c '[^[:space:]]' <<< "$body" || true)
        if [ "$n" -lt 1 ]; then echo "static: the code of $f is empty"; bad=1; continue; fi
        for pat in "${FORBIDDEN[@]}"; do
            if grep -Eq -- "$pat" <<< "$body"; then echo "static: $f matches the forbidden pattern $pat"; bad=1; fi
        done
    done
    return "$bad"
}
