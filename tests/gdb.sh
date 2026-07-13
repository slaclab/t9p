#!/usr/bin/env bash
set -e
while getopts "t:" o; do
    case "${o}" in
    t)
        TGT="${OPTARG}"
        ;;
    *)
        echo "Unknown arg ${o}"
        exit 1
        ;;
    esac
done

if [ -z "${TGT}" ]; then
    echo "Needs -t TGT (ex: i386-rtems-pc386)"
    exit 1
fi

ARCH=$(echo ${TGT} | cut -d '-' -f1)

$ARCH-rtems7-gdb -ex 'target remote localhost:1234' -ex "symbol-file build/${TGT}/t9p_rtems_test"
