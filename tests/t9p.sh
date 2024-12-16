#!/usr/bin/env bash

cd "$(dirname "${BASH_SOURCE[0]}")"

$DEBUGGER ../t9p -i $(id -u) -a $PWD/fs -m $PWD/mnt 0.0.0.0:10002
