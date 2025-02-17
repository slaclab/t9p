#!/usr/bin/env bash

cd "$(dirname "${BASH_SOURCE[0]}")"

$DEBUGGER ../build/t9p_threaded_test -i $(id -u) -a "$PWD/fs" -m "$PWD/mnt" 0.0.0.0:10002 -n 4 -t 10 $@
