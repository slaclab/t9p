#!/usr/bin/env bash

set -e

cd "$(dirname "${BASH_SOURCE[0]}")"

QEMU_ARGS=""
ARCH=i386
TARGET=rtems6-pc686-qemu

while test $# -gt 0; do
    case $1 in
    --gdb)
        QEMU_ARGS="$QEMU_ARGS -s -S"
        ;;
    -a|--arch)
        ARCH=$2
        shift
        ;;
    -t|--target)
        TARGET=$2
        shift
        ;;
    *)
        echo "Unknown arg $1"
        exit 1
        ;;
    esac
    shift
done

# diod running on host port 10002
BSP_ARGS="--console=/dev/com1 -u jeremy -a $PWD/fs -m $PWD/mnt 10.0.2.2:10002"

qemu-system-$ARCH $QEMU_ARGS -no-reboot -serial mon:stdio -nographic \
    -device e1000,netdev=em0 -netdev user,id=em0,hostfwd=tcp::10003-:10003,hostfwd=tcp::1234-:1234 \
    -append "$BSP_ARGS" -kernel $PWD/../build-$TARGET/t9p_rtems_test
