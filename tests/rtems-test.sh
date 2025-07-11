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
    -l|--limit)
        LIMIT="cpulimit -f -l 1 --"
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
BSP_ARGS="--console=/dev/com1 -u $(whoami) -a $PWD/fs -m $PWD/mnt 10.0.2.2:10002"

if [[ "$(echo $TARGET | cut -d '-' -f1)" == "rtems4" ]]; then
    NETDEV=ne2k_pci
else
    NETDEV=e1000
fi
echo "NETDEV=$NETDEV"

gcc -o tcpsrv tcpsrv.c -lc
./tcpsrv &

$LIMIT qemu-system-$ARCH $QEMU_ARGS -no-reboot -m 128M -serial mon:stdio -nographic \
    -device $NETDEV,netdev=em0 -netdev user,id=em0,hostfwd=tcp::10003-:10003,hostfwd=tcp::1234-:1234,hostfwd=udp::5000-:5000 \
    -append "$BSP_ARGS" -kernel $PWD/../build-cmake/build-$TARGET/t9p_rtems_test

kill $(jobs -p)