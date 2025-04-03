#!/usr/bin/env bash

cd "$(dirname "${BASH_SOURCE[0]}")"

$DEBUGGER ../build-cmake/build-linux-x86_64/t9p_threaded_test -i $(id -u) -a "$PWD/fs" -m "$PWD/mnt" 0.0.0.0:10002 -n 1 -t 16 $@
