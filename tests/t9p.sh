#!/usr/bin/env bash

cd "$(dirname "${BASH_SOURCE[0]}")"

$DEBUGGER ../build/t9p_cmd -i $(id -u) -a $PWD/fs -m $PWD/mnt 0.0.0.0:10002
