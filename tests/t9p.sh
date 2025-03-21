#!/usr/bin/env bash

cd "$(dirname "${BASH_SOURCE[0]}")"

HARCH=$(uname -m)

EXEC=../build-cmake/build-linux-$HARCH/t9p_cmd
QEMU=
while test $# -gt 0; do
    case $1 in
    --arch|-a)
        ARCH="$2"
        shift 2
        EXEC="../build-$ARCH-linux/t9p_cmd"
        ;;
    *)
        echo "USAGE: $0 [-a arch]"
        exit 1
        ;;
    esac
done

if [ "$ARCH" = "powerpc" ] || [ "$ARCH" = "ppc" ]; then
    QEMU="qemu-powerpc -cpu 7457"
fi

$DEBUGGER $QEMU $EXEC -i $(id -u) -a $PWD/fs -m $PWD/mnt 0.0.0.0:10002
