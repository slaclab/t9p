#!/usr/bin/env bash

set -e

cd "$(dirname "${BASH_SOURCE[0]}")"

#if [ -z "$RTEMS_TOP" ]; then
#    echo "Set RTEMS_TOP to the top directory of your SLAC RTEMS installation"
#    exit 1
#fi

#"$RTEMS_TOP/scripts/run-i386-qemu.sh" "$PWD/../build-i386-rtems/t9p_rtems_test" $@ 

#qemu-system-i386 -kernel $PWD/../build-i386-rtems/t9p_rtems_test -serial mon:stdio -device ne2k_isa,netdev=if0 \
#    -netdev user,id=if0,hostfwd=tcp::5075-:5075,hostfwd=udp::5076-:5076 -m 1024 --no-reboot -nographic -append "--video=off --console=/dev/com1" $@

qemu-system-i386 -no-reboot -serial stdio -monitor none -nographic -s -S \
    -append "--console=/dev/com1" -kernel $PWD/../build-i386-rtems/t9p_rtems_test
