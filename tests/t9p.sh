#!/usr/bin/env bash

cd "$(dirname "${BASH_SOURCE[0]}")"

$DEBUGGER ../t9p -i 16626 -a `readlink -f $PWD/fs` -m $PWD/mnt 0.0.0.0:10002
