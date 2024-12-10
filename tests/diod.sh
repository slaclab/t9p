#!/usr/bin/env bash
set -e

cd "$(dirname "${BASH_SOURCE[0]}")"

if ! which diod > /dev/null; then
    echo "Unable to find diod. Make sure it's installed and that you are running as root"
fi

DAEMON=0
while test $# -gt 0; do
    case $1 in
    -d)
        DAEMON=1
        ;;
    *)
        ;;
    esac
    shift
done

ARGS=
if [ $DAEMON -eq 0 ]; then
    ARGS="$ARGS -f"
fi

/sbin/diod $ARGS -L stderr -e $PWD/fs -l 0.0.0.0:10002 -n
