#!/usr/bin/env bash

set -e

cd "$(dirname "${BASH_SOURCE[0]}")"

if [ -z "$RTEMS_TOP" ]; then
    echo "Set RTEMS_TOP to the top directory of your SLAC RTEMS installation"
    exit 1
fi

"$RTEMS_TOP/scripts/run-arm-qemu.sh" "$PWD/../build-arm-rtems/t9p_rtems_test" $@ 
