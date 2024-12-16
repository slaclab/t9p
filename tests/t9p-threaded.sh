#!/usr/bin/env bash

cd "$(dirname "${BASH_SOURCE[0]}")"

$DEBUGGER ./t9p_threaded_test -i $(id -u) -a "$(readlink -f $PWD/fs)" -m "$(readlink -f $PWD/mnt)" 0.0.0.0:10002 -n 4 -t 0.2 $@
