#!/usr/bin/env bash
set -e

cd "$(dirname "${BASH_SOURCE[0]}")"

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

if [ -z "$DIOD" ]; then
	DIOD=diod
fi

$DEBUGGER $DIOD $ARGS -L stderr -d5 -e "$PWD/fs" -l 0.0.0.0:10002 -n
